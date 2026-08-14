"""
make_dataset_benign_scripts.py

data/raw 아래의 모든 ASP, ASPX, JSP, JSPX, PS1 파일을 재귀적으로 찾아
기존 preprocessor.py의 Feature를 그대로 추출한다.

새로운 Feature를 추가하지 않으며, 출력 열은 다음 순서를 유지한다.
    label, filename, filepath, *FEATURE_ORDER

실행:
    프로젝트 루트에서
    python src/preprocessing/make_dataset_benign_scripts.py

출력:
    data/preprocessed/dataset_benign_scripts.csv
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

import pandas as pd

# 직접 실행 / module 실행 모두 지원
try:
    from .preprocessor import FEATURE_ORDER, preprocess_many
except ImportError:
    from preprocessor import FEATURE_ORDER, preprocess_many


# project/src/preprocessing/make_dataset_benign_scripts.py 기준
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DATA_DIR = PROJECT_ROOT / "data/raw"
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "data/preprocessed/dataset_benign_scripts.csv"
)

TARGET_EXTENSIONS = {
    ".asp",
    ".aspx",
    ".jsp",
    ".jspx",
    ".ps1",
}


def collect_files(directory: Path) -> list[Path]:
    """대상 확장자 파일을 하위 폴더까지 재귀적으로 수집한다."""
    if not directory.exists():
        return []

    return sorted(
        path
        for path in directory.rglob("*")
        if path.is_file()
        and path.suffix.lower() in TARGET_EXTENSIONS
        and ".git" not in path.parts
    )


def make_dataset_benign_scripts(
    output_csv: str | Path = DEFAULT_OUTPUT,
) -> pd.DataFrame:
    """정상 웹·PowerShell 스크립트의 기존 Feature Dataset을 생성한다."""
    print(f"프로젝트 루트: {PROJECT_ROOT}")
    print(f"원시 데이터 경로: {RAW_DATA_DIR}")
    print()

    # 1. data/raw 전체에서 지정 확장자만 수집
    files = collect_files(RAW_DATA_DIR)
    extension_counts = Counter(path.suffix.lower() for path in files)

    print("[1/3] 정상 스크립트 파일 수집 완료")
    for extension in sorted(TARGET_EXTENSIONS):
        print(f"  {extension:<5}: {extension_counts[extension]:,}개")
    print(f"  합계 : {len(files):,}개")

    if not files:
        extensions = ", ".join(sorted(TARGET_EXTENSIONS))
        raise FileNotFoundError(
            "처리할 파일이 없습니다.\n"
            f"- 검색 경로: {RAW_DATA_DIR}\n"
            f"- 대상 확장자: {extensions}"
        )

    # 2. 기존 preprocessor.py를 변경하지 않고 그대로 사용
    print()
    print("[2/3] 기존 Feature 추출 중...")
    features = preprocess_many(files)

    if len(features) != len(files):
        raise RuntimeError(
            "처리된 Feature 수와 입력 파일 수가 일치하지 않습니다."
        )

    # 3. 기존 Dataset 형식으로 DataFrame 생성
    rows = []

    for file_path, feature in zip(files, features):
        row = dict(feature)
        row["label"] = "benign"
        row["filename"] = file_path.name
        row["filepath"] = file_path.relative_to(PROJECT_ROOT).as_posix()
        rows.append(row)

    columns = [
        "label",
        "filename",
        "filepath",
    ] + FEATURE_ORDER

    df = pd.DataFrame(rows, columns=columns)

    output_csv = Path(output_csv)
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
    print(f"  파일 수  : {len(df):,}개")
    print(f"  Feature  : {len(FEATURE_ORDER)}개")
    print(f"  전체 열  : {len(df.columns)}개")

    print()
    print("Label 분포:")
    print(df["label"].value_counts().to_string())

    print()
    print("확장자 분포:")
    print(
        df["filename"]
        .map(lambda name: Path(name).suffix.lower())
        .value_counts()
        .sort_index()
        .to_string()
    )

    return df


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "data/raw 아래의 ASP, ASPX, JSP, JSPX, PS1 파일을 "
            "기존 Feature Dataset CSV로 변환"
        )
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=(
            "출력 CSV 경로 "
            "(기본값: data/preprocessed/dataset_benign_scripts.csv)"
        ),
    )

    args = parser.parse_args()
    make_dataset_benign_scripts(args.output)


if __name__ == "__main__":
    main()
