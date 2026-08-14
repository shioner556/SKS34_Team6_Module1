#!/usr/bin/env python3
"""Extract existing preprocessor features from benign and Mitra image data.

No new feature is introduced. FEATURE_ORDER from preprocessor.py is the
authoritative feature schema and column order.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

try:
    from .preprocessor import FEATURE_ORDER, preprocess_many
except ImportError:
    from preprocessor import FEATURE_ORDER, preprocess_many


METADATA_COLUMNS = ["label", "source", "dataset", "sample_number", "filename", "filepath"]
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}
IGNORED_DIR_NAMES = {"metadata", "logs", "work", "__pycache__"}
IGNORED_FILE_EXTENSIONS = {".csv", ".json", ".log", ".txt", ".md"}


@dataclass(frozen=True)
class Sample:
    path: Path
    label: int
    source: str
    dataset: str


def project_root_from_script() -> Path:
    # project/src/preprocessing/make_dataset_image_anomaly.py -> project
    return Path(__file__).resolve().parents[2]


def relative_to_project(path: Path, project_root: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def source_name(path: Path, root: Path, fallback: str) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return fallback
    return relative.parts[0] if len(relative.parts) > 1 else fallback


def iter_benign(root: Path) -> Iterator[Sample]:
    if not root.is_dir():
        raise FileNotFoundError(f"benign directory not found: {root}")
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in IMAGE_EXTENSIONS:
            continue
        if any(part.lower() in IGNORED_DIR_NAMES for part in path.relative_to(root).parts[:-1]):
            continue
        yield Sample(
            path=path,
            label=0,
            source=source_name(path, root, "benign"),
            dataset="image_anomaly_benign",
        )


def iter_mitra(root: Path) -> Iterator[Sample]:
    if not root.is_dir():
        raise FileNotFoundError(f"Mitra output directory not found: {root}")
    files_root = root / "files"
    scan_root = files_root if files_root.is_dir() else root
    for path in sorted(scan_root.rglob("*")):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(scan_root).parts[:-1]
        if any(part.lower() in IGNORED_DIR_NAMES for part in relative_parts):
            continue
        if path.suffix.lower() in IGNORED_FILE_EXTENSIONS:
            continue
        yield Sample(
            path=path,
            label=1,
            source="mitra",
            dataset="image_anomaly_mitra",
        )


def batches(items: list[Sample], size: int) -> Iterable[list[Sample]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def write_dataset(
    samples: list[Sample],
    output: Path,
    project_root: Path,
    batch_size: int,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    columns = METADATA_COLUMNS + list(FEATURE_ORDER)
    total = len(samples)

    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()

        processed = 0
        for sample_batch in batches(samples, batch_size):
            paths = [sample.path for sample in sample_batch]
            features = preprocess_many(paths)
            if len(features) != len(sample_batch):
                raise RuntimeError(
                    "preprocess_many result length mismatch: "
                    f"inputs={len(sample_batch)}, outputs={len(features)}"
                )

            rows = []
            for offset, (sample, feature) in enumerate(zip(sample_batch, features), start=1):
                feature_mapping = dict(feature)
                metadata = {
                    "label": sample.label,
                    "source": sample.source,
                    "dataset": sample.dataset,
                    "sample_number": processed + offset,
                    "filename": sample.path.name,
                    "filepath": relative_to_project(sample.path, project_root),
                }
                # Only existing FEATURE_ORDER fields are emitted.
                row = {**metadata, **{name: feature_mapping.get(name) for name in FEATURE_ORDER}}
                rows.append(row)
            writer.writerows(rows)
            handle.flush()
            processed += len(sample_batch)
            print(f"Processed {processed}/{total}")


def parse_args() -> argparse.Namespace:
    project_root = project_root_from_script()
    parser = argparse.ArgumentParser(
        description="Create a benign/Mitra image anomaly CSV with the existing preprocessor features."
    )
    parser.add_argument(
        "--benign",
        type=Path,
        default=project_root / "data/raw/image_anomaly/benign",
    )
    parser.add_argument(
        "--mitra",
        type=Path,
        default=project_root / "data/raw/image_anomaly/anomalous/mitra",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=project_root / "data/preprocessed/dataset_image_anomaly.csv",
    )
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--benign-only", action="store_true")
    parser.add_argument("--mitra-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.batch_size < 1:
        raise SystemExit("--batch-size must be at least 1")
    if args.benign_only and args.mitra_only:
        raise SystemExit("--benign-only and --mitra-only cannot be used together")

    project_root = project_root_from_script()
    samples: list[Sample] = []
    if not args.mitra_only:
        samples.extend(iter_benign(args.benign.resolve()))
    if not args.benign_only:
        samples.extend(iter_mitra(args.mitra.resolve()))
    if not samples:
        raise SystemExit("No input files found")

    benign_count = sum(sample.label == 0 for sample in samples)
    mitra_count = sum(sample.label == 1 for sample in samples)
    print(f"Benign: {benign_count}")
    print(f"Mitra anomalous: {mitra_count}")
    print(f"Features: {len(FEATURE_ORDER)}")
    print(f"Output: {args.output.resolve()}")

    write_dataset(samples, args.output.resolve(), project_root, args.batch_size)
    print("Dataset creation complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
