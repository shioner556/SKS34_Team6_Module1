"""
make_dataset_bazaar.py

프로젝트 구조:
project/
├── src/
│   └── preprocessing/
│       ├── preprocessor.py
│       └── make_dataset_bazaar.py
├── data/
│   ├── raw/
│   │   ├
│   │   └── malware_bazaar/  악성 웹쉘 파일 (하위 폴더 포함)
│   └── preprocessed/          전처리가 완료된 .csv 파일
└── ...

실행:
    프로젝트 루트에서
    python src/preprocessing/make_dataset_bazaar.py

출력:
    data/preprocessed/dataset_bazaar.csv
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


# 프로젝트 루트 경로 (project/src/preprocessing/make_dataset_bazaar.py 기준)
PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DATA_DIR = PROJECT_ROOT / "data/raw"
BENIGN_WEBSHELL_DIR = RAW_DATA_DIR / "benign_bazaar"
MALWARE_WEBSHELL_DIR = RAW_DATA_DIR / "malware_bazaar"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/preprocessed/dataset_bazaar.csv"


def collect_files(directory: Path) -> list[Path]:
    """
    폴더 아래의 모든 실제 파일을 재귀적으로 수집한다.
    rglob('*')을 사용하므로 몇 단계 아래의 하위 폴더가 존재해도 모두 수집된다.
    """
    if not directory.exists():
        return []

    return sorted(
        path
        for path in directory.rglob("*")
        if path.is_file()
    )


def make_dataset_bazaar(
    output_csv: str | Path = DEFAULT_OUTPUT,
) -> pd.DataFrame:
    """benign_bazaar/malware_bazaar 파일들을 preprocess_many()로 처리하여 CSV를 생성한다."""

    print(f"프로젝트 루트: {PROJECT_ROOT}")
    print(f"웹쉘 원시 데이터 경로: {RAW_DATA_DIR}")
    print()

    # 1. 하위 폴더까지 포함하여 파일 수집
    benign_files = collect_files(BENIGN_WEBSHELL_DIR)
    malware_files = collect_files(MALWARE_WEBSHELL_DIR)
    all_files = benign_files + malware_files

    print("[1/3] 웹쉘 파일 수집 (하위 폴더 탐색 완료)")
    print(f"  benign_bazaar : {len(benign_files)}개")
    print(f"  malware_bazaar: {len(malware_files)}개")

    if not all_files:
        raise FileNotFoundError(
            f"처리할 웹쉘 파일이 없습니다. 경로를 확인해주세요:\n"
            f"- 정상 폴더: {BENIGN_WEBSHELL_DIR}\n"
            f"- 악성 폴더: {MALWARE_WEBSHELL_DIR}"
        )

    # 2. 여러 파일을 한 번에 전처리
    print()
    print("[2/3] Feature 추출 중...")

    features = preprocess_many(all_files)

    if len(features) != len(all_files):
        raise RuntimeError(
            "처리된 Feature 수와 파일 수가 일치하지 않습니다."
        )

    # 3. DataFrame 생성 및 라벨링
    rows = []

    for file_path, feature in zip(all_files, features):
        row = dict(feature)

        # 추적용 메타데이터
        row["filename"] = file_path.name
        row["filepath"] = str(
            file_path.relative_to(PROJECT_ROOT)
        )

        # 폴더 위치에 따른 label 결정 (기존 ML 파이프라인과의 호환성을 위해 benign / malware로 지정)
        if file_path.is_relative_to(BENIGN_WEBSHELL_DIR):
            row["label"] = "benign"
        elif file_path.is_relative_to(MALWARE_WEBSHELL_DIR):
            row["label"] = "malware"
        else:
            row["label"] = "unknown"

        rows.append(row)

    df = pd.DataFrame(rows)

    # Feature 37개 + 메타데이터 3개 (label, filename, filepath)
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
    print("[3/3] 웹쉘 Dataset 생성 완료")
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
        description="raw/benign_bazaar 및 malware_bazaar 내 파일을 탐색하여 Dataset CSV로 변환"
    )

    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="출력 CSV 경로 (기본값: data/preprocessed/dataset_bazaar.csv)",
    )

    args = parser.parse_args()
    make_dataset_bazaar(args.output)


if __name__ == "__main__":
    main()