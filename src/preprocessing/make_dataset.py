"""
make_dataset.py

프로젝트 구조:
project/
├── src/
│   └── preprocessing/
│       ├── preprocessor.py
│       └── make_dataset.py
├── data/
│   ├── raw/
│   │   ├── benign/ 정상 파일
│   │   └── malware/ 악성 파일
│   └── preprocessed/ 전처리가 완료된 .csv 파일
└── ...

실행:
    프로젝트 루트에서
    python src/preprocessing/make_dataset.py

출력:
    data/preprocessed/dataset.csv
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

# 직접 실행 / module 실행 모두 지원
try:
    from .preprocessor import preprocess_many, FEATURE_ORDER
except ImportError:
    from preprocessor import preprocess_many, FEATURE_ORDER


# 현재:
# project/src/preprocessing/make_dataset.py
# parents[2] == project/
PROJECT_ROOT = Path(__file__).resolve().parents[2]

TEST_SAMPLES_DIR = PROJECT_ROOT / "data/raw"
BENIGN_DIR = TEST_SAMPLES_DIR / "benign"
MALWARE_DIR = TEST_SAMPLES_DIR / "malware"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/preprocessed/dataset.csv"


def collect_files(directory: Path) -> list[Path]:
    """폴더 아래의 모든 실제 파일을 재귀적으로 수집한다."""
    if not directory.exists():
        return []

    return sorted(
        path
        for path in directory.rglob("*")
        if path.is_file()
    )


def make_dataset(
    output_csv: str | Path = DEFAULT_OUTPUT,
) -> pd.DataFrame:
    """benign/malware 파일을 preprocess_many()로 처리하여 CSV를 만든다."""

    print(f"프로젝트 루트: {PROJECT_ROOT}")
    print(f"테스트 데이터: {TEST_SAMPLES_DIR}")
    print()

    # 1. 파일 수집
    benign_files = collect_files(BENIGN_DIR)
    malware_files = collect_files(MALWARE_DIR)
    all_files = benign_files + malware_files

    print("[1/3] 파일 수집")
    print(f"  benign : {len(benign_files)}개")
    print(f"  malware: {len(malware_files)}개")

    if not all_files:
        raise FileNotFoundError(
            f"처리할 파일이 없습니다: {TEST_SAMPLES_DIR}"
        )

    # 2. 여러 파일을 한 번에 전처리
    print()
    print("[2/3] Feature 추출 중...")

    features = preprocess_many(all_files)

    if len(features) != len(all_files):
        raise RuntimeError(
            "처리된 Feature 수와 파일 수가 일치하지 않습니다."
        )

    # 3. DataFrame 생성
    rows = []

    for file_path, feature in zip(all_files, features):
        row = dict(feature)

        # 추적용 메타데이터
        row["filename"] = file_path.name
        row["filepath"] = str(
            file_path.relative_to(PROJECT_ROOT)
        )

        # 폴더에 따라 label 결정
        if file_path.is_relative_to(BENIGN_DIR):
            row["label"] = "benign"
        elif file_path.is_relative_to(MALWARE_DIR):
            row["label"] = "malware"
        else:
            row["label"] = "unknown"

        rows.append(row)

    df = pd.DataFrame(rows)

    # Feature 37개 + metadata 3개
    df = df[[
        "label",
        "filename",
        "filepath",
    ] + FEATURE_ORDER]

    output_csv = Path(output_csv)

    # 상대 경로는 프로젝트 루트 기준
    if not output_csv.is_absolute():
        output_csv = PROJECT_ROOT / output_csv

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(
        output_csv,
        index=False,
        encoding="utf-8-sig",
    )

    print()
    print("[3/3] Dataset 생성 완료")
    print(f"  저장 위치: {output_csv}")
    print(f"  파일 수  : {len(df)}개")
    print(f"  Feature  : {len(FEATURE_ORDER)}개")
    print(f"  전체 열  : {len(df.columns)}개")

    print()
    print("Label 분포:")
    print(df["label"].value_counts().to_string())

    return df


def main() -> None:
    parser = argparse.ArgumentParser(
        description="test_samples를 Feature Dataset CSV로 변환"
    )

    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="출력 CSV 경로 (기본값: 프로젝트 루트/dataset.csv)",
    )

    args = parser.parse_args()
    make_dataset(args.output)


if __name__ == "__main__":
    main()
