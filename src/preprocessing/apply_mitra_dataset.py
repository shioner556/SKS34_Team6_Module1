#!/usr/bin/env python3
"""Apply Mitra to collected images and write a reproducible manifest.

This is an orchestration script: Mitra decides which polyglot layouts are
possible. Use only inert payloads in an isolated dataset workspace.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from pathlib import Path


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}
DEFAULT_PAYLOAD_EXTENSIONS = {".pdf", ".zip", ".html", ".htm", ".txt", ".bin"}


@dataclass
class Record:
    pair_id: str
    source_id: str
    source_path: str
    source_sha256: str
    source_extension: str
    payload_id: str
    payload_path: str
    payload_sha256: str
    payload_extension: str
    output_path: str
    output_name_original: str
    output_sha256: str
    output_size: int
    mitra_layout: str
    reverse_enabled: bool
    generated_at: str


@dataclass
class Failure:
    pair_id: str
    source_path: str
    payload_path: str
    return_code: int
    reason: str
    stderr: str
    occurred_at: str


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def append_csv(path: Path, rows: list[object], row_type: type[object]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    names = [field.name for field in fields(row_type)]
    header = not path.exists() or path.stat().st_size == 0
    with path.open("a", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=names)
        if header:
            writer.writeheader()
        writer.writerows(asdict(row) for row in rows)


def files_under(root: Path, extensions: set[str]) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in extensions)


def completed_pairs(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open(encoding="utf-8-sig", newline="") as file:
        return {row["pair_id"] for row in csv.DictReader(file)}


def layout_from_name(name: str) -> str:
    prefixes = {"S": "stack", "C": "cavity", "P": "parasite", "Z": "zipper", "O": "overlap"}
    match = re.match(r"^([SCPZO])(?:\(|-)", name, re.IGNORECASE)
    return prefixes.get(match.group(1).upper(), "unknown") if match else "unknown"


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "file"


def validate_args(args: argparse.Namespace) -> None:
    if not args.mitra.is_file():
        raise SystemExit(f"Mitra 실행 파일을 찾을 수 없습니다: {args.mitra}")
    if not args.images.is_dir() or not args.payloads.is_dir():
        raise SystemExit("이미지 또는 payload 디렉터리를 찾을 수 없습니다.")
    if args.output.resolve() in args.images.resolve().parents or args.output.resolve() == args.images.resolve():
        raise SystemExit("출력 디렉터리를 원본 이미지 디렉터리 내부/동일 경로로 지정할 수 없습니다.")


def main() -> int:
    parser = argparse.ArgumentParser(description="The Met 이미지에 Mitra polyglot 생성 적용")
    parser.add_argument("--mitra", type=Path, default=Path("tools/mitra/mitra.py"))
    parser.add_argument("--images", type=Path, default=Path("data/raw/image_anomaly/benign/met"))
    parser.add_argument("--payloads", type=Path, default=Path("data/raw/image_anomaly/payloads"))
    parser.add_argument("--output", type=Path, default=Path("data/raw/image_anomaly/anomalous/mitra"))
    parser.add_argument("--reverse", action="store_true", help="Mitra -r 옵션 사용")
    parser.add_argument("--overlap", action="store_true", help="고급 near-polyglot 생성")
    parser.add_argument("--timeout", type=int, default=120, help="조합당 제한 시간(초)")
    parser.add_argument("--max-images", type=int, default=0, help="0이면 전부")
    parser.add_argument("--max-payloads", type=int, default=0, help="0이면 전부")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    validate_args(args)

    images = files_under(args.images, IMAGE_EXTENSIONS)
    payloads = files_under(args.payloads, DEFAULT_PAYLOAD_EXTENSIONS)
    if args.max_images:
        images = images[: args.max_images]
    if args.max_payloads:
        payloads = payloads[: args.max_payloads]
    if not images or not payloads:
        raise SystemExit(f"입력 부족: images={len(images)}, payloads={len(payloads)}")

    manifest = args.output / "metadata" / "mitra_manifest.csv"
    failures_path = args.output / "metadata" / "mitra_failures.csv"
    summary_path = args.output / "metadata" / "mitra_summary.json"
    done = completed_pairs(manifest)
    records: list[Record] = []
    failures: list[Failure] = []
    attempted = skipped = generated = 0

    for image in images:
        source_hash = sha256(image)
        source_id = image.stem
        for payload in payloads:
            payload_hash = sha256(payload)
            pair_id = hashlib.sha256(f"{source_hash}:{payload_hash}:{args.reverse}:{args.overlap}".encode()).hexdigest()[:20]
            if pair_id in done:
                skipped += 1
                continue
            attempted += 1
            pair_dir = args.output / "work" / pair_id
            final_dir = args.output / "files" / image.suffix.lower().lstrip(".") / source_id / pair_id
            command = [sys.executable, str(args.mitra.resolve()), str(image.resolve()), str(payload.resolve()),
                       "--outdir", str(pair_dir.resolve())]
            if args.reverse:
                command.append("--reverse")
            if args.overlap:
                command.append("--overlap")
            if args.dry_run:
                print(" ".join(command))
                continue
            pair_dir.mkdir(parents=True, exist_ok=True)
            before = {path.resolve() for path in pair_dir.rglob("*") if path.is_file()}
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout, check=False)
                after = {path.resolve() for path in pair_dir.rglob("*") if path.is_file()}
                new_files = sorted(after - before)
                if result.returncode != 0 or not new_files:
                    reason = "mitra_error" if result.returncode else "unsupported_pair_or_no_output"
                    failures.append(Failure(pair_id, str(image), str(payload), result.returncode, reason,
                                            result.stderr[-4000:], now()))
                    shutil.rmtree(pair_dir, ignore_errors=True)
                    continue
                final_dir.mkdir(parents=True, exist_ok=True)
                for index, produced in enumerate(new_files, start=1):
                    original_name = produced.name
                    suffixes = "".join(produced.suffixes) or ".bin"
                    destination = final_dir / f"{safe_component(source_id)}__{safe_component(payload.stem)}__{index:03d}{suffixes}"
                    shutil.move(str(produced), destination)
                    records.append(Record(
                        pair_id, source_id, str(image), source_hash, image.suffix.lower(), payload.stem,
                        str(payload), payload_hash, payload.suffix.lower(), str(destination), original_name,
                        sha256(destination), destination.stat().st_size, layout_from_name(original_name),
                        args.reverse, now(),
                    ))
                    generated += 1
                done.add(pair_id)
                shutil.rmtree(pair_dir, ignore_errors=True)
            except subprocess.TimeoutExpired as exc:
                failures.append(Failure(pair_id, str(image), str(payload), -1, "timeout",
                                        (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "", now()))
                shutil.rmtree(pair_dir, ignore_errors=True)

            if len(records) + len(failures) >= 25:
                append_csv(manifest, records, Record)
                append_csv(failures_path, failures, Failure)
                records.clear()
                failures.clear()

    append_csv(manifest, records, Record)
    append_csv(failures_path, failures, Failure)
    summary = {
        "images": len(images), "payloads": len(payloads), "attempted_pairs": attempted,
        "skipped_completed_pairs": skipped, "generated_files": generated,
        "reverse": args.reverse, "overlap": args.overlap, "finished_at": now(),
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
