#!/usr/bin/env python3
"""Run independent image collectors concurrently and build one manifest.

Required sibling scripts:
  - collect_wikimedia_images.py
  - collect_met_images.py

Each collector keeps its own licence-rich metadata. This orchestrator only
coordinates processes and creates a compact cross-source integrity manifest.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from PIL import Image, UnidentifiedImageError


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}
FORMAT_EXTENSION = {"JPEG": ".jpg", "PNG": ".png", "GIF": ".gif", "BMP": ".bmp", "TIFF": ".tiff", "WEBP": ".webp"}


@dataclass(frozen=True)
class CollectorJob:
    name: str
    command: list[str]
    log_path: Path


def parse_sources(value: str) -> list[str]:
    supported = {"wikimedia", "met", "loc"}
    sources = list(dict.fromkeys(item.strip().lower() for item in value.split(",") if item.strip()))
    unknown = sorted(set(sources) - supported)
    if unknown:
        raise argparse.ArgumentTypeError(f"unsupported sources: {', '.join(unknown)}")
    if not sources:
        raise argparse.ArgumentTypeError("at least one source is required")
    return sources


def run_job(job: CollectorJob, cwd: Path) -> tuple[str, int, Path]:
    job.log_path.parent.mkdir(parents=True, exist_ok=True)
    with job.log_path.open("w", encoding="utf-8", errors="replace") as log:
        log.write("COMMAND: " + subprocess.list2cmdline(job.command) + "\n\n")
        log.flush()
        process = subprocess.Popen(
            job.command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            log.write(line)
            log.flush()
            print(f"[{job.name}] {line}", end="")
        return job.name, process.wait(), job.log_path


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_image(path: Path) -> dict[str, object]:
    file_size = path.stat().st_size
    digest = sha256_file(path)
    try:
        with Image.open(path) as image:
            image.verify()
        with Image.open(path) as image:
            image_format = (image.format or "").upper()
            width, height = image.size
    except (UnidentifiedImageError, OSError) as exc:
        return {
            "valid_image": 0, "detected_format": "", "width": "", "height": "",
            "file_size": file_size, "sha256": digest,
            "error": f"{type(exc).__name__}: {exc}",
        }
    expected = FORMAT_EXTENSION.get(image_format, "")
    return {
        "valid_image": 1, "detected_format": image_format,
        "width": width, "height": height, "file_size": file_size,
        "sha256": digest,
        "error": "" if expected and path.suffix.lower() in {expected, ".jpeg" if expected == ".jpg" else expected, ".tif" if expected == ".tiff" else expected}
        else f"extension mismatch: {path.suffix} vs {image_format}",
    }


def iter_images(source_roots: dict[str, Path]) -> Iterable[tuple[str, Path]]:
    for source, root in source_roots.items():
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS and "metadata" not in path.parts:
                yield source, path


def build_manifest(
    source_roots: dict[str, Path],
    project_root: Path,
    manifest_path: Path,
    summary_path: Path,
    workers: int,
) -> dict[str, object]:
    images = list(iter_images(source_roots))
    rows: list[dict[str, object]] = []
    lock = threading.Lock()

    def inspect(item: tuple[str, Path]) -> dict[str, object]:
        source, path = item
        result = inspect_image(path)
        try:
            relative = path.resolve().relative_to(project_root).as_posix()
        except ValueError:
            relative = path.resolve().as_posix()
        return {"source": source, "file_path": relative, "extension": path.suffix.lower(), **result}

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = [executor.submit(inspect, item) for item in images]
        for future in as_completed(futures):
            with lock:
                rows.append(future.result())

    rows.sort(key=lambda row: (str(row["source"]), str(row["file_path"])))
    hash_counts: dict[str, int] = {}
    for row in rows:
        digest = str(row["sha256"])
        hash_counts[digest] = hash_counts.get(digest, 0) + 1
    for row in rows:
        row["duplicate_sha256"] = int(hash_counts[str(row["sha256"])] > 1)

    fields = (
        "source", "file_path", "extension", "detected_format", "valid_image",
        "width", "height", "file_size", "sha256", "duplicate_sha256", "error",
    )
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    by_source: dict[str, int] = {}
    by_format: dict[str, int] = {}
    for row in rows:
        source = str(row["source"])
        extension = str(row["extension"])
        by_source[source] = by_source.get(source, 0) + 1
        by_format[extension] = by_format.get(extension, 0) + 1
    summary: dict[str, object] = {
        "total_files": len(rows),
        "valid_images": sum(int(row["valid_image"]) for row in rows),
        "invalid_images": sum(not int(row["valid_image"]) for row in rows),
        "duplicate_files": sum(int(row["duplicate_sha256"]) for row in rows),
        "by_source": by_source,
        "by_extension": by_format,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Wikimedia, The Met, and LOC collectors concurrently.")
    parser.add_argument("--output", type=Path, default=Path("data/raw/image_anomaly/benign"))
    parser.add_argument("--sources", type=parse_sources, default=parse_sources("wikimedia,loc"))
    parser.add_argument("--wikimedia-limit", default="jpg=100,png=200,gif=100,tiff=50")
    parser.add_argument("--met-limit", default="jpg=200")
    parser.add_argument("--loc-limit", type=int, default=200)
    parser.add_argument("--loc-workers", type=int, default=8)
    parser.add_argument("--loc-api-delay", type=float, default=0.2)
    parser.add_argument("--loc-allow-unclear-rights", action="store_true")
    parser.add_argument("--wikimedia-workers", type=int, default=8)
    parser.add_argument("--wikimedia-api-delay", type=float, default=1.0)
    parser.add_argument("--candidate-factor", type=int, default=2)
    parser.add_argument("--max-file-mb", type=float, default=10.0)
    parser.add_argument("--met-delay", type=float, default=0.1)
    parser.add_argument("--max-objects", type=int, default=0)
    parser.add_argument("--manifest-workers", type=int, default=max(2, min(8, os.cpu_count() or 2)))
    parser.add_argument("--skip-manifest", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parents[1] if script_dir.name == "preprocessing" else Path.cwd().resolve()
    output = args.output if args.output.is_absolute() else project_root / args.output
    output = output.resolve()
    logs = output / "metadata" / "logs"
    jobs: list[CollectorJob] = []
    roots: dict[str, Path] = {}

    if "wikimedia" in args.sources:
        script = script_dir / "collect_wikimedia_images.py"
        if not script.exists():
            raise SystemExit(f"missing collector: {script}")
        target = output / "wikimedia"
        roots["wikimedia"] = target
        jobs.append(CollectorJob("wikimedia", [
            sys.executable, str(script), "--output", str(target),
            "--limit", args.wikimedia_limit,
            "--workers", str(args.wikimedia_workers),
            "--candidate-factor", str(args.candidate_factor),
            "--api-delay", str(args.wikimedia_api_delay),
            "--max-file-mb", str(args.max_file_mb),
        ], logs / "wikimedia.log"))

    if "met" in args.sources:
        script = script_dir / "collect_met_images.py"
        if not script.exists():
            raise SystemExit(f"missing collector: {script}")
        target = output / "met"
        roots["met"] = target
        command = [
            sys.executable, str(script), "--output", str(target),
            "--limit", args.met_limit, "--max-mb", str(args.max_file_mb),
            "--delay", str(args.met_delay),
        ]
        if args.max_objects:
            command.extend(["--max-objects", str(args.max_objects)])
        jobs.append(CollectorJob("met", command, logs / "met.log"))

    if "loc" in args.sources:
        script = script_dir / "collect_loc_tiff_images.py"
        if not script.exists():
            raise SystemExit(f"missing collector: {script}")
        target = output / "loc"
        roots["loc"] = target
        command = [
            sys.executable, str(script), "--output", str(target),
            "--limit", str(args.loc_limit), "--workers", str(args.loc_workers),
            "--api-delay", str(args.loc_api_delay), "--max-file-mb", str(args.max_file_mb),
        ]
        if args.loc_allow_unclear_rights:
            command.append("--allow-unclear-rights")
        jobs.append(CollectorJob("loc", command, logs / "loc.log"))

    print(f"Starting concurrently: {', '.join(job.name for job in jobs)}")
    statuses: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        futures = {executor.submit(run_job, job, project_root): job for job in jobs}
        for future in as_completed(futures):
            name, return_code, log_path = future.result()
            statuses[name] = return_code
            print(f"[{name}] finished with code {return_code}; log={log_path}")

    summary: dict[str, object] = {"collector_exit_codes": statuses}
    if not args.skip_manifest:
        metadata = output / "metadata"
        summary.update(build_manifest(
            roots, project_root, metadata / "all_source_images.csv",
            metadata / "collection_summary.json", args.manifest_workers,
        ))
        # Re-write once so collector statuses are also retained.
        (metadata / "collection_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    # Some collectors use exit code 2 for target shortfall; preserve it as a warning.
    return 1 if any(code not in {0, 2} for code in statuses.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
