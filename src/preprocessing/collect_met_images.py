#!/usr/bin/env python3
"""Collect public-domain images from The Metropolitan Museum of Art API.

The downloaded bytes are never transcoded. Files are classified by their
decoded image format, and provenance is recorded in CSV files.

Example:
    python collect_met_images.py --output data/raw/image_anomaly/benign/met \
        --limit jpg=500,png=100,gif=100,bmp=100,tiff=100,webp=100
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import logging
import random
import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from PIL import Image, UnidentifiedImageError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


API_ROOT = "https://collectionapi.metmuseum.org/public/collection/v1"
DEFAULT_LIMITS = {"jpg": 500, "png": 100, "gif": 100, "bmp": 100,
                  "tiff": 100, "webp": 100}
FORMAT_TO_EXTENSION = {
    "JPEG": "jpg",
    "PNG": "png",
    "GIF": "gif",
    "BMP": "bmp",
    "TIFF": "tiff",
    "WEBP": "webp",
}


@dataclass
class ImageRecord:
    source_id: str
    object_id: int
    image_index: int
    image_role: str
    file_path: str
    detected_format: str
    mime_type: str
    title: str
    creator: str
    object_page_url: str
    image_url: str
    license: str
    width: int
    height: int
    file_size: int
    sha256: str
    downloaded_at: str
    department: str
    object_name: str
    medium: str


@dataclass
class ErrorRecord:
    object_id: int
    image_url: str
    stage: str
    error: str
    occurred_at: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_limits(value: str) -> dict[str, int]:
    allowed = set(DEFAULT_LIMITS)
    result: dict[str, int] = {}
    for item in value.split(","):
        try:
            extension, count = item.strip().lower().split("=", 1)
            extension = {"jpeg": "jpg", "tif": "tiff"}.get(extension, extension)
            number = int(count)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                "형식은 jpg=500,png=100처럼 입력해야 합니다."
            ) from exc
        if extension not in allowed or number < 0:
            raise argparse.ArgumentTypeError(f"지원하지 않는 값: {item}")
        result[extension] = number
    return result


def build_session(user_agent: str) -> requests.Session:
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        status=5,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def api_json(session: requests.Session, url: str, *, timeout: float) -> dict[str, Any]:
    response = session.get(url, timeout=timeout)
    response.raise_for_status()
    return response.json()


def append_csv(path: Path, records: list[Any], record_type: type[Any]) -> None:
    if not records:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    names = [field.name for field in fields(record_type)]
    write_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=names)
        if write_header:
            writer.writeheader()
        writer.writerows(asdict(record) for record in records)


def load_state(metadata_path: Path) -> tuple[set[str], set[int], dict[str, int]]:
    hashes: set[str] = set()
    completed_objects: set[int] = set()
    counts = {extension: 0 for extension in DEFAULT_LIMITS}
    if not metadata_path.exists():
        return hashes, completed_objects, counts
    with metadata_path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            hashes.add(row["sha256"])
            completed_objects.add(int(row["object_id"]))
            extension = row["detected_format"].lower()
            if extension in counts:
                counts[extension] += 1
    return hashes, completed_objects, counts


def inspect_image(content: bytes) -> tuple[str, int, int]:
    with Image.open(io.BytesIO(content)) as image:
        image.verify()
    with Image.open(io.BytesIO(content)) as image:
        detected = FORMAT_TO_EXTENSION.get((image.format or "").upper())
        if not detected:
            raise ValueError(f"지원하지 않는 이미지 형식: {image.format!r}")
        width, height = image.size
    return detected, width, height


def safe_text(value: Any) -> str:
    return "" if value is None else str(value).replace("\x00", "").strip()


def image_candidates(obj: dict[str, Any], include_additional: bool) -> list[tuple[str, str, int]]:
    result: list[tuple[str, str, int]] = []
    primary = safe_text(obj.get("primaryImage"))
    if primary:
        result.append((primary, "primary", 0))
    if include_additional:
        for index, url in enumerate(obj.get("additionalImages") or [], start=1):
            if safe_text(url):
                result.append((safe_text(url), "additional", index))
    return result


def collect(args: argparse.Namespace) -> dict[str, Any]:
    output: Path = args.output
    metadata_dir = output / "metadata"
    metadata_path = metadata_dir / "met_images.csv"
    error_path = metadata_dir / "met_download_errors.csv"
    summary_path = metadata_dir / "met_collection_summary.json"
    for extension in args.limit:
        (output / extension).mkdir(parents=True, exist_ok=True)

    session = build_session(args.user_agent)
    hashes, completed_objects, counts = load_state(metadata_path)
    logging.info("기존 수집량: %s", counts)

    search_url = f"{API_ROOT}/search"
    response = session.get(
        search_url,
        params={"hasImages": "true", "isPublicDomain": "true", "q": args.query},
        timeout=args.timeout,
    )
    response.raise_for_status()
    object_ids = response.json().get("objectIDs") or []
    if args.seed is not None:
        random.Random(args.seed).shuffle(object_ids)

    pending_images: list[ImageRecord] = []
    pending_errors: list[ErrorRecord] = []
    scanned = 0

    def goals_met() -> bool:
        return all(counts[ext] >= target for ext, target in args.limit.items())

    for object_id in object_ids:
        if goals_met() or (args.max_objects and scanned >= args.max_objects):
            break
        if object_id in completed_objects:
            continue
        scanned += 1
        try:
            obj = api_json(session, f"{API_ROOT}/objects/{object_id}", timeout=args.timeout)
            if not obj.get("isPublicDomain"):
                continue
        except (requests.RequestException, ValueError) as exc:
            pending_errors.append(ErrorRecord(object_id, "", "metadata", repr(exc), utc_now()))
            continue

        for image_url, role, image_index in image_candidates(obj, args.include_additional):
            try:
                image_response = session.get(image_url, timeout=args.timeout)
                image_response.raise_for_status()
                content = image_response.content
                if len(content) > args.max_bytes:
                    raise ValueError(f"파일 크기 제한 초과: {len(content)} bytes")
                extension, width, height = inspect_image(content)
                if extension not in args.limit or counts[extension] >= args.limit[extension]:
                    continue
                if min(width, height) < args.min_dimension:
                    raise ValueError(f"최소 크기 미달: {width}x{height}")

                digest = hashlib.sha256(content).hexdigest()
                if digest in hashes:
                    continue
                source_id = f"met_{object_id}_{role}_{image_index:03d}"
                destination = output / extension / f"{source_id}.{extension}"
                destination.write_bytes(content)
                hashes.add(digest)
                counts[extension] += 1
                pending_images.append(ImageRecord(
                    source_id=source_id,
                    object_id=object_id,
                    image_index=image_index,
                    image_role=role,
                    file_path=destination.as_posix(),
                    detected_format=extension,
                    mime_type=image_response.headers.get("Content-Type", "").split(";", 1)[0],
                    title=safe_text(obj.get("title")),
                    creator=safe_text(obj.get("artistDisplayName")),
                    object_page_url=safe_text(obj.get("objectURL")),
                    image_url=image_url,
                    license="CC0 / Public Domain (The Met Open Access)",
                    width=width,
                    height=height,
                    file_size=len(content),
                    sha256=digest,
                    downloaded_at=utc_now(),
                    department=safe_text(obj.get("department")),
                    object_name=safe_text(obj.get("objectName")),
                    medium=safe_text(obj.get("medium")),
                ))
                logging.info("저장: %s (%dx%d)", destination, width, height)
            except (requests.RequestException, UnidentifiedImageError, OSError, ValueError) as exc:
                pending_errors.append(ErrorRecord(object_id, image_url, "download", repr(exc), utc_now()))

        if len(pending_images) + len(pending_errors) >= args.flush_every:
            append_csv(metadata_path, pending_images, ImageRecord)
            append_csv(error_path, pending_errors, ErrorRecord)
            pending_images.clear()
            pending_errors.clear()
        if args.delay:
            time.sleep(args.delay)

    append_csv(metadata_path, pending_images, ImageRecord)
    append_csv(error_path, pending_errors, ErrorRecord)
    summary = {
        "requested": args.limit,
        "collected_total": {key: counts[key] for key in args.limit},
        "shortfall": {key: max(0, target - counts[key]) for key, target in args.limit.items()},
        "objects_scanned_this_run": scanned,
        "query": args.query,
        "generated_at": utc_now(),
        "note": "Original bytes preserved; no format conversion was performed.",
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="The Met CC0 이미지 형식별 수집기")
    parser.add_argument("--output", type=Path, default=Path("data/raw/image_anomaly/benign/met"))
    parser.add_argument("--limit", type=parse_limits, default=DEFAULT_LIMITS.copy(),
                        help="형식별 목표량. 예: jpg=500,png=100,tiff=100")
    parser.add_argument("--query", default="*", help="The Met 검색어")
    parser.add_argument("--include-additional", action="store_true", help="대표 이미지 외 추가 이미지도 수집")
    parser.add_argument("--min-dimension", type=int, default=256)
    parser.add_argument("--max-mb", type=float, default=20.0)
    parser.add_argument("--max-objects", type=int, default=0, help="0이면 제한 없음")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--delay", type=float, default=0.05, help="작품 요청 사이 대기 시간(초)")
    parser.add_argument("--flush-every", type=int, default=25)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--user-agent", default="SKS34-Team6-Dataset-Collector/1.0")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if any(value < 0 for value in args.limit.values()):
        parser.error("목표 수량은 0 이상이어야 합니다.")
    if args.min_dimension < 1 or args.max_mb <= 0 or args.flush_every < 1:
        parser.error("크기 및 저장 주기 옵션은 양수여야 합니다.")
    args.max_bytes = int(args.max_mb * 1024 * 1024)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        summary = collect(args)
    except requests.RequestException as exc:
        logging.error("The Met API 요청 실패: %s", exc)
        return 1
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
