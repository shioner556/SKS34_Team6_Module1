#!/usr/bin/env python3
"""Collect low-resolution, openly licensed images from Wikimedia Commons.

The script uses the MediaWiki API, accepts only CC0/Public Domain licences,
downloads Wikimedia-generated thumbnails concurrently, preserves metadata,
and removes byte-identical duplicates with SHA-256.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable

import requests
from PIL import Image, UnidentifiedImageError


API_URL = "https://commons.wikimedia.org/w/api.php"
USER_AGENT = "SKS34-Team6-ImageDataset/1.0 (academic research; Wikimedia Commons API)"
ALLOWED_FORMATS = {"JPEG": "jpg", "PNG": "png", "GIF": "gif", "BMP": "bmp", "TIFF": "tiff", "WEBP": "webp"}
FORMAT_MIME = {
    "jpg": "image/jpeg", "png": "image/png", "gif": "image/gif",
    "bmp": "image/bmp", "tiff": "image/tiff", "webp": "image/webp",
}
DEFAULT_LIMITS = {"jpg": 300, "png": 300, "gif": 100, "bmp": 100, "tiff": 100, "webp": 100}
ALLOWED_LICENSES = {
    "cc0", "cc-zero", "public domain", "pd", "pdm", "public domain mark",
}
DEFAULT_QUERIES = (
    "nature", "landscape", "animal", "plant", "food", "building", "object",
    "painting", "photograph", "texture", "vehicle", "architecture",
)
CSV_FIELDS = (
    "source_id", "file_path", "extension", "source_type", "title", "description",
    "creator", "license", "license_url", "attribution", "commons_page_url",
    "original_url", "thumbnail_url", "width", "height", "file_size", "sha256",
    "query", "downloaded_at",
)


@dataclass(frozen=True)
class Candidate:
    page_id: int
    title: str
    query: str
    page_url: str
    original_url: str
    thumbnail_url: str
    license_name: str
    license_url: str
    creator: str
    attribution: str
    description: str
    requested_format: str


def clean_html(value: Any) -> str:
    """Strip simple HTML from Commons extmetadata without extra dependencies."""
    import html
    import re

    text = str(value or "")
    text = re.sub(r"<[^>]+>", " ", text)
    return " ".join(html.unescape(text).split())


def metadata_value(metadata: dict[str, Any], key: str) -> str:
    item = metadata.get(key, {})
    return clean_html(item.get("value", "") if isinstance(item, dict) else item)


def licence_allowed(name: str, usage_terms: str, license_url: str) -> bool:
    combined = f"{name} {usage_terms} {license_url}".lower()
    return any(token in combined for token in ALLOWED_LICENSES)


def api_get(
    session: requests.Session,
    params: dict[str, Any],
    retries: int = 8,
    api_delay: float = 0.5,
) -> dict[str, Any]:
    last_error = "unknown error"
    for attempt in range(retries):
        try:
            response = session.get(API_URL, params=params, timeout=(10, 45))
            if response.status_code in {429, 502, 503, 504}:
                retry_after = response.headers.get("Retry-After", "")
                try:
                    wait_seconds = float(retry_after)
                except ValueError:
                    wait_seconds = min(2 ** attempt, 60)
                wait_seconds = max(wait_seconds, api_delay)
                last_error = f"HTTP {response.status_code}; retry after {wait_seconds:g}s"
                print(f"Wikimedia API busy ({last_error}), retry {attempt + 1}/{retries}")
                time.sleep(wait_seconds)
                continue
            response.raise_for_status()
            payload = response.json()
            api_error = payload.get("error")
            if api_error:
                code = api_error.get("code", "unknown")
                message = api_error.get("info", "Wikimedia API error")
                if code == "maxlag":
                    wait_seconds = min(2 ** attempt, 30)
                    last_error = f"maxlag: {message}"
                    print(f"Wikimedia API lagged, waiting {wait_seconds}s ({attempt + 1}/{retries})")
                    time.sleep(wait_seconds)
                    continue
                raise RuntimeError(f"Wikimedia API {code}: {message}")
            time.sleep(api_delay)
            return payload
        except (requests.RequestException, ValueError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt + 1 == retries:
                raise RuntimeError(f"Wikimedia API failed after {retries} attempts: {last_error}") from exc
            wait_seconds = min(2 ** attempt, 30)
            print(f"Wikimedia API request failed ({last_error}), waiting {wait_seconds}s")
            time.sleep(wait_seconds)
    raise RuntimeError(f"Wikimedia API failed after {retries} attempts: {last_error}")


def find_candidates(
    session: requests.Session,
    queries: Iterable[str],
    thumb_width: int,
    max_candidates: int,
    requested_format: str,
    api_delay: float,
) -> list[Candidate]:
    found: dict[int, Candidate] = {}
    for query in queries:
        continuation: dict[str, Any] = {}
        while len(found) < max_candidates:
            params: dict[str, Any] = {
                "action": "query", "format": "json", "formatversion": 2,
                "generator": "search", "gsrnamespace": 6,
                "gsrsearch": f"{query} filetype:bitmap filemime:{FORMAT_MIME[requested_format]}", "gsrlimit": 50,
                "prop": "imageinfo", "iiprop": "url|size|mime|extmetadata",
                "iiurlwidth": thumb_width,
                "iiextmetadatafilter": "LicenseShortName|LicenseUrl|UsageTerms|Artist|Attribution|ImageDescription",
                "maxlag": 5,
            }
            params.update(continuation)
            payload = api_get(session, params, api_delay=api_delay)
            for page in payload.get("query", {}).get("pages", []):
                info_list = page.get("imageinfo") or []
                if not info_list:
                    continue
                info = info_list[0]
                if info.get("mime", "").lower() != FORMAT_MIME[requested_format]:
                    continue
                meta = info.get("extmetadata") or {}
                license_name = metadata_value(meta, "LicenseShortName")
                license_url = metadata_value(meta, "LicenseUrl")
                usage_terms = metadata_value(meta, "UsageTerms")
                if not licence_allowed(license_name, usage_terms, license_url):
                    continue
                page_id = int(page["pageid"])
                found[page_id] = Candidate(
                    page_id=page_id,
                    title=page["title"],
                    query=query,
                    page_url=f"https://commons.wikimedia.org/?curid={page_id}",
                    original_url=info.get("url", ""),
                    thumbnail_url=info.get("thumburl") or info.get("url", ""),
                    license_name=license_name or usage_terms,
                    license_url=license_url,
                    creator=metadata_value(meta, "Artist"),
                    attribution=metadata_value(meta, "Attribution"),
                    description=metadata_value(meta, "ImageDescription"),
                    requested_format=requested_format,
                )
                if len(found) >= max_candidates:
                    break
            continuation = payload.get("continue") or {}
            if not continuation or len(found) >= max_candidates:
                break
    candidates = list(found.values())
    random.Random(42).shuffle(candidates)
    return candidates


def download_one(candidate: Candidate, timeout: int) -> tuple[Candidate, bytes, str, int, int]:
    # Original bytes are required: Commons may transcode GIF/TIFF thumbnails to JPEG/PNG.
    response = requests.get(candidate.original_url, headers={"User-Agent": USER_AGENT}, timeout=(10, timeout))
    response.raise_for_status()
    data = response.content
    try:
        with Image.open(BytesIO(data)) as image:
            image.verify()
        with Image.open(BytesIO(data)) as image:
            fmt = (image.format or "").upper()
            width, height = image.size
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError(f"invalid image: {exc}") from exc
    extension = ALLOWED_FORMATS.get(fmt)
    if not extension:
        raise ValueError(f"unsupported decoded format: {fmt or 'unknown'}")
    if extension != candidate.requested_format:
        raise ValueError(f"format mismatch: requested={candidate.requested_format}, decoded={extension}")
    return candidate, data, extension, width, height


def read_existing_hashes(csv_path: Path) -> tuple[set[str], set[int], list[dict[str, str]]]:
    hashes: set[str] = set()
    page_ids: set[int] = set()
    rows: list[dict[str, str]] = []
    if csv_path.exists():
        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                rows.append(row)
                if row.get("sha256"):
                    hashes.add(row["sha256"])
                source_id = row.get("source_id", "")
                if source_id.startswith("commons_"):
                    try:
                        page_ids.add(int(source_id.removeprefix("commons_")))
                    except ValueError:
                        pass
    return hashes, page_ids, rows


def write_csv(path: Path, rows: list[dict[str, Any]], fields: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect CC0/Public Domain Wikimedia Commons thumbnails quickly.")
    parser.add_argument("--output", type=Path, default=Path("data/raw/image_anomaly/benign/wikimedia"))
    parser.add_argument(
        "--limit", default=",".join(f"{key}={value}" for key, value in DEFAULT_LIMITS.items()),
        help="Per-format targets, e.g. jpg=300,png=300,gif=100,bmp=100,tiff=100,webp=100",
    )
    parser.add_argument("--thumb-width", type=int, default=512, help="Requested thumbnail width in pixels")
    parser.add_argument("--workers", type=int, default=16, help="Concurrent image downloads (recommended: 8-24)")
    parser.add_argument("--candidate-factor", type=int, default=4, help="Candidates searched per missing image")
    parser.add_argument("--api-delay", type=float, default=0.5, help="Delay after each successful API request")
    parser.add_argument("--query", action="append", dest="queries", help="Repeatable Commons search term")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--max-file-mb", type=float, default=10.0)
    return parser.parse_args()


def parse_limits(value: str) -> dict[str, int]:
    limits: dict[str, int] = {}
    aliases = {"jpeg": "jpg", "tif": "tiff"}
    for item in value.split(","):
        if not item.strip():
            continue
        try:
            raw_name, raw_count = item.split("=", 1)
            name = aliases.get(raw_name.strip().lower(), raw_name.strip().lower())
            count = int(raw_count)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid --limit item: {item!r}") from exc
        if name not in FORMAT_MIME:
            raise argparse.ArgumentTypeError(f"unsupported format in --limit: {name}")
        if count < 0:
            raise argparse.ArgumentTypeError("format limits cannot be negative")
        limits[name] = count
    if not limits or sum(limits.values()) == 0:
        raise argparse.ArgumentTypeError("--limit must contain at least one positive target")
    return limits


def main() -> int:
    args = parse_args()
    try:
        limits = parse_limits(args.limit)
    except argparse.ArgumentTypeError as exc:
        raise SystemExit(str(exc)) from exc
    if args.thumb_width < 64 or args.workers < 1 or args.api_delay < 0:
        raise SystemExit("--workers must be positive; --thumb-width >= 64 and --api-delay >= 0 are required")

    output = args.output.resolve()
    metadata_dir = output / "metadata"
    manifest_path = metadata_dir / "wikimedia_images.csv"
    errors_path = metadata_dir / "wikimedia_download_errors.csv"
    summary_path = metadata_dir / "wikimedia_collection_summary.json"
    output.mkdir(parents=True, exist_ok=True)
    existing_hashes, existing_pages, rows = read_existing_hashes(manifest_path)
    current: dict[str, int] = {name: 0 for name in limits}
    for row in rows:
        extension = row.get("extension", "").lstrip(".").lower()
        if extension in current:
            current[extension] += 1
    missing_by_format = {name: max(target - current[name], 0) for name, target in limits.items()}
    if sum(missing_by_format.values()) == 0:
        print(f"Already complete: {current}")
        return 0

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"})
    queries = args.queries or list(DEFAULT_QUERIES)
    candidates: list[Candidate] = []
    for format_name, missing in missing_by_format.items():
        if missing == 0:
            continue
        candidate_count = max(missing * args.candidate_factor, missing + 30)
        print(f"Searching {format_name}: target {missing}, up to {candidate_count} candidates...")
        found = find_candidates(session, queries, args.thumb_width, candidate_count, format_name, args.api_delay)
        candidates.extend(c for c in found if c.page_id not in existing_pages)
    print(f"Downloading with {args.workers} workers from {len(candidates)} candidates...")

    errors: list[dict[str, str]] = []
    lock = threading.Lock()
    max_bytes = int(args.max_file_mb * 1024 * 1024)
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(download_one, item, args.timeout): item for item in candidates}
        for future in as_completed(futures):
            if all(current[name] >= target for name, target in limits.items()):
                for pending in futures:
                    pending.cancel()
                break
            candidate = futures[future]
            try:
                item, data, extension, width, height = future.result()
                if current.get(extension, 0) >= limits.get(extension, 0):
                    continue
                if len(data) > max_bytes:
                    raise ValueError(f"file exceeds {args.max_file_mb:g} MiB")
                digest = hashlib.sha256(data).hexdigest()
                with lock:
                    if digest in existing_hashes:
                        continue
                    existing_hashes.add(digest)
                    target_dir = output / extension
                    target_dir.mkdir(parents=True, exist_ok=True)
                    target = target_dir / f"commons_{item.page_id}.{extension}"
                    target.write_bytes(data)
                    relative = target.relative_to(Path.cwd()).as_posix() if target.is_relative_to(Path.cwd()) else target.as_posix()
                    rows.append({
                        "source_id": f"commons_{item.page_id}", "file_path": relative,
                        "extension": f".{extension}", "source_type": "native_original",
                        "title": item.title, "description": item.description,
                        "creator": item.creator, "license": item.license_name,
                        "license_url": item.license_url, "attribution": item.attribution,
                        "commons_page_url": item.page_url, "original_url": item.original_url,
                        "thumbnail_url": item.thumbnail_url, "width": width, "height": height,
                        "file_size": len(data), "sha256": digest, "query": item.query,
                        "downloaded_at": datetime.now(timezone.utc).isoformat(),
                    })
                    current[extension] = current.get(extension, 0) + 1
                    print(f"[{extension} {current[extension]:>4}/{limits[extension]}] {target.name} ({width}x{height})")
            except Exception as exc:
                errors.append({"source_id": f"commons_{candidate.page_id}", "title": candidate.title,
                               "url": candidate.thumbnail_url, "error": f"{type(exc).__name__}: {exc}"})

    write_csv(manifest_path, rows, CSV_FIELDS)
    write_csv(errors_path, errors, ("source_id", "title", "url", "error"))
    by_format: dict[str, int] = {}
    for row in rows:
        by_format[row["extension"]] = by_format.get(row["extension"], 0) + 1
    summary = {
        "requested_by_format": limits, "collected_by_format": by_format,
        "shortfall_by_format": {name: max(target - by_format.get(f".{name}", 0), 0) for name, target in limits.items()},
        "download_mode": "original", "workers": args.workers,
        "accepted_licenses": ["CC0", "Public Domain"], "by_format": by_format,
        "errors_this_run": len(errors), "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    metadata_dir.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if all(by_format.get(f".{name}", 0) >= target for name, target in limits.items()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
