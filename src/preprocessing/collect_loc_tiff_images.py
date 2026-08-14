#!/usr/bin/env python3
"""Collect openly reusable TIFF images from the Library of Congress JSON API."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import requests
from PIL import Image, UnidentifiedImageError


SEARCH_URL = "https://www.loc.gov/photos/"
USER_AGENT = "SKS34-Team6-ImageDataset/1.0 (academic research)"
OPEN_RIGHTS_MARKERS = (
    "public domain", "no known restrictions", "free to use", "freely available",
    "no copyright restriction", "copyright not evaluated",
)
CSV_FIELDS = (
    "source_id", "file_path", "extension", "source_type", "title", "date",
    "creator", "rights", "rights_url", "item_url", "download_url", "mime_type",
    "width", "height", "file_size", "sha256", "downloaded_at",
)


def request_json(session: requests.Session, url: str, params: dict[str, Any] | None, retries: int, delay: float) -> dict[str, Any]:
    last_error = "unknown"
    for attempt in range(retries):
        try:
            response = session.get(url, params=params, timeout=(10, 60))
            if response.status_code in {429, 500, 502, 503, 504}:
                retry_after = response.headers.get("Retry-After", "")
                try:
                    wait = float(retry_after)
                except ValueError:
                    wait = min(2 ** attempt, 60)
                last_error = f"HTTP {response.status_code}"
                time.sleep(max(wait, delay))
                continue
            response.raise_for_status()
            payload = response.json()
            time.sleep(delay)
            return payload
        except (requests.RequestException, ValueError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt + 1 < retries:
                time.sleep(min(2 ** attempt, 30))
    raise RuntimeError(f"LOC request failed after {retries} attempts: {last_error}")


def flatten_text(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        output: list[str] = []
        for item in value.values():
            output.extend(flatten_text(item))
        return output
    if isinstance(value, list):
        output = []
        for item in value:
            output.extend(flatten_text(item))
        return output
    return []


def first_text(value: Any) -> str:
    values = flatten_text(value)
    return " | ".join(dict.fromkeys(text.strip() for text in values if text.strip()))


def rights_text(record: dict[str, Any]) -> str:
    candidates = []
    for key in ("rights", "rights_advisory", "rights_information", "restriction", "access_restricted"):
        if key in record:
            candidates.extend(flatten_text(record[key]))
    item = record.get("item")
    if isinstance(item, dict):
        for key in ("rights", "rights_advisory", "rights_information"):
            candidates.extend(flatten_text(item.get(key)))
    return " | ".join(dict.fromkeys(text.strip() for text in candidates if text.strip()))


def has_open_rights(record: dict[str, Any]) -> bool:
    text = rights_text(record).lower()
    return any(marker in text for marker in OPEN_RIGHTS_MARKERS)


def iter_file_objects(value: Any) -> Iterable[dict[str, Any]]:
    """Yield nested LOC file descriptors regardless of collection schema depth."""
    if isinstance(value, dict):
        url = value.get("url") or value.get("download") or value.get("href")
        mime = value.get("mimetype") or value.get("mime_type") or value.get("mime")
        if isinstance(url, str) and (mime or Path(urlparse(url).path).suffix):
            yield value
        for child in value.values():
            yield from iter_file_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_file_objects(child)


def tiff_urls(record: dict[str, Any]) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for descriptor in iter_file_objects(record.get("resources", record)):
        url = descriptor.get("url") or descriptor.get("download") or descriptor.get("href")
        if not isinstance(url, str) or not url.startswith("http"):
            continue
        mime = str(descriptor.get("mimetype") or descriptor.get("mime_type") or descriptor.get("mime") or "").lower()
        suffix = Path(urlparse(url).path).suffix.lower()
        if mime in {"image/tiff", "image/tif"} or suffix in {".tif", ".tiff"}:
            found[url] = mime or "image/tiff"
    return list(found.items())


def record_id(record: dict[str, Any]) -> str:
    value = record.get("id") or record.get("item", {}).get("id", "")
    if isinstance(value, list):
        value = value[0] if value else ""
    token = str(value).rstrip("/").split("/")[-1]
    return "".join(ch for ch in token if ch.isalnum() or ch in "-_") or hashlib.sha1(str(value).encode()).hexdigest()[:16]


def detail_url(result: dict[str, Any]) -> str:
    value = result.get("id") or result.get("url") or ""
    if isinstance(value, list):
        value = value[0] if value else ""
    url = str(value)
    return url if url.startswith("http") else f"https://www.loc.gov{url}"


def download_tiff(url: str, timeout: int, max_bytes: int) -> tuple[bytes, int, int]:
    response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=(10, timeout), stream=True)
    response.raise_for_status()
    declared = int(response.headers.get("Content-Length", 0) or 0)
    if declared > max_bytes:
        raise ValueError(f"declared file size exceeds limit: {declared}")
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(1024 * 1024):
        size += len(chunk)
        if size > max_bytes:
            raise ValueError(f"download exceeds limit: {size}")
        chunks.append(chunk)
    data = b"".join(chunks)
    try:
        with Image.open(BytesIO(data)) as image:
            image.verify()
        with Image.open(BytesIO(data)) as image:
            if (image.format or "").upper() != "TIFF":
                raise ValueError(f"decoded as {image.format}, not TIFF")
            return data, image.width, image.height
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError(f"invalid TIFF: {exc}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect TIFF files from open Library of Congress records.")
    parser.add_argument("--output", type=Path, default=Path("data/raw/image_anomaly/benign/loc"))
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--query", action="append", dest="queries")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--rows", type=int, default=100, choices=range(1, 101), metavar="1-100")
    parser.add_argument("--max-pages", type=int, default=50)
    parser.add_argument("--api-delay", type=float, default=0.2)
    parser.add_argument("--max-file-mb", type=float, default=30.0)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--allow-unclear-rights", action="store_true", help="Internal-only fallback; still records LOC rights text")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = args.output.resolve()
    image_dir = output / "tiff"
    metadata = output / "metadata"
    manifest = metadata / "loc_tiff_images.csv"
    errors_path = metadata / "loc_tiff_errors.csv"
    summary_path = metadata / "loc_tiff_summary.json"
    image_dir.mkdir(parents=True, exist_ok=True)
    metadata.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    hashes: set[str] = set()
    if manifest.exists():
        with manifest.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
            hashes = {row["sha256"] for row in rows if row.get("sha256")}
    if len(rows) >= args.limit:
        print(f"Already complete: {len(rows)}/{args.limit}")
        return 0

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"})
    queries = args.queries or ["photograph", "poster", "map", "drawing", "architecture"]
    details: list[dict[str, Any]] = []
    seen_details: set[str] = set()
    for query in queries:
        for page in range(1, args.max_pages + 1):
            payload = request_json(session, SEARCH_URL, {"fo": "json", "c": args.rows, "sp": page, "q": query}, 6, args.api_delay)
            results = payload.get("results") or []
            if not results:
                break
            urls = [detail_url(result) for result in results]
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {executor.submit(request_json, session, url, {"fo": "json"}, 6, args.api_delay): url for url in urls if url not in seen_details}
                for future in as_completed(futures):
                    url = futures[future]
                    seen_details.add(url)
                    try:
                        record = future.result()
                        if args.allow_unclear_rights or has_open_rights(record):
                            if tiff_urls(record):
                                details.append(record)
                    except Exception as exc:
                        print(f"DETAIL_ERROR {url}: {exc}")
            if len(details) >= max((args.limit - len(rows)) * 2, 50):
                break
        if len(details) >= max((args.limit - len(rows)) * 2, 50):
            break

    errors: list[dict[str, str]] = []
    jobs: list[tuple[dict[str, Any], str, str, int]] = []
    for record in details:
        for index, (url, mime) in enumerate(tiff_urls(record)):
            jobs.append((record, url, mime, index))
    max_bytes = int(args.max_file_mb * 1024 * 1024)
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(download_tiff, url, args.timeout, max_bytes): (record, url, mime, index) for record, url, mime, index in jobs}
        for future in as_completed(futures):
            if len(rows) >= args.limit:
                for pending in futures:
                    pending.cancel()
                break
            record, url, mime, index = futures[future]
            rid = record_id(record)
            try:
                data, width, height = future.result()
                digest = hashlib.sha256(data).hexdigest()
                with lock:
                    if digest in hashes:
                        continue
                    hashes.add(digest)
                    path = image_dir / f"loc_{rid}_{index:02d}.tiff"
                    path.write_bytes(data)
                    item = record.get("item") if isinstance(record.get("item"), dict) else record
                    rows.append({
                        "source_id": f"loc_{rid}_{index:02d}", "file_path": path.as_posix(),
                        "extension": ".tiff", "source_type": "native_original",
                        "title": first_text(item.get("title", record.get("title", ""))),
                        "date": first_text(item.get("date", record.get("date", ""))),
                        "creator": first_text(item.get("contributor_names", item.get("contributors", ""))),
                        "rights": rights_text(record), "rights_url": first_text(item.get("rights_url", "")),
                        "item_url": detail_url(record), "download_url": url, "mime_type": mime,
                        "width": width, "height": height, "file_size": len(data), "sha256": digest,
                        "downloaded_at": datetime.now(timezone.utc).isoformat(),
                    })
                    print(f"[{len(rows):>4}/{args.limit}] {path.name} ({width}x{height})")
            except Exception as exc:
                errors.append({"source_id": rid, "url": url, "error": f"{type(exc).__name__}: {exc}"})

    with manifest.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    with errors_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("source_id", "url", "error"))
        writer.writeheader()
        writer.writerows(errors)
    summary = {"requested": args.limit, "collected": len(rows), "shortfall": max(args.limit - len(rows), 0),
               "errors_this_run": len(errors), "allow_unclear_rights": args.allow_unclear_rights,
               "completed_at": datetime.now(timezone.utc).isoformat()}
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if len(rows) >= args.limit else 2


if __name__ == "__main__":
    raise SystemExit(main())
