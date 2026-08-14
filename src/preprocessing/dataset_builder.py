"""
builder.py - 9개 소스별 독립 dataset_*.csv 가공 모듈

지원 데이터셋 접미어 (총 9종):
1. arxiv_pdf
2. bazaar
3. benign_scripts
4. cic_evasive_pdf_mal
5. dike
6. image_anomaly
7. napierone
8. webshell
9. wordpress_php

실행 방법:
    # 9개 각각의 dataset_*.csv 를 순차적으로 모두 생성/갱신
    python src/preprocessing/builder.py --all

    # 특정 데이터셋 하나만 생성/갱신 (예: napierone)
    python src/preprocessing/builder.py --target napierone
"""

from __future__ import annotations

import argparse
from pathlib import Path
import pandas as pd

# preprocessor 모듈 임포트
try:
    from .preprocessor import preprocess_many, FEATURE_ORDER
except ImportError:
    from preprocessor import preprocess_many, FEATURE_ORDER

# 프로젝트 루트 경로 (src/preprocessing/builder.py 기준 상위 2단계)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "preprocessed"

# 9개 데이터셋 접미어 목록
DATASET_SUFFIXES = [
    "arxiv_pdf",
    "bazaar",
    "benign_scripts",
    "cic_evasive_pdf_mal",
    "dike",
    "image_anomaly",
    "napierone",
    "webshell",
    "wordpress_php",
]


def get_dataset_config(suffix: str) -> dict:
    """접미어를 기반으로 입력 디렉터리 및 대상 CSV 파일 경로 반환"""
    # image_anomaly의 경우 파일명 호환성 유지 (41cols)
    csv_name = (
        "dataset_image_anomaly_41cols.csv"
        if suffix == "image_anomaly"
        else f"dataset_{suffix}.csv"
    )

    return {
        "suffix": suffix,
        "benign_dir": RAW_DATA_DIR / f"benign_{suffix}",
        "malware_dir": RAW_DATA_DIR / f"malware_{suffix}",
        "output_csv": PROCESSED_DIR / csv_name,
    }


def collect_files(directory: Path) -> list[Path]:
    """디렉터리 내의 모든 유효한 파일 수집 (무시할 확장자/폴더 제외)"""
    if not directory or not directory.exists():
        return []

    ignored_names = {"metadata", "logs", "work", "__pycache__", ".git"}
    ignored_exts = {".csv", ".json", ".log", ".txt", ".md", ".py", ".pyc"}

    files = []
    for p in directory.rglob("*"):
        if p.is_file():
            if any(part in ignored_names for part in p.parts):
                continue
            if p.suffix.lower() in ignored_exts:
                continue
            files.append(p)
    return files

def load_existing_processed_paths(csv_path: Path) -> tuple[set[str], set[str]]:
    """
    기존 CSV에서 이미 처리된 (1) 절대경로 집합과 (2) 파일명 집합을 함께 반환
    """
    if not csv_path.exists():
        return set(), set()
    try:
        df = pd.read_csv(csv_path)
        existing_paths = set()
        existing_filenames = set()

        # 1. filepath 컬럼이 있는 경우 (절대/상대 경로 정규화)
        path_col = None
        for col in ["filepath", "file_path", "path"]:
            if col in df.columns:
                path_col = col
                break

        if path_col:
            for p in df[path_col].dropna().astype(str):
                # 윈도우/리눅스 경로 통일 및 소문자 정규화
                norm_p = str(Path(p).resolve()).lower()
                existing_paths.add(norm_p)
                existing_filenames.add(Path(p).name.lower())

        # 2. filename 컬럼이 있는 경우
        if "filename" in df.columns:
            for fn in df["filename"].dropna().astype(str):
                existing_filenames.add(fn.lower())

        return existing_paths, existing_filenames
    except Exception as e:
        print(f"  ⚠️ 기존 CSV 읽기 중 알림: {e}")
        return set(), set()


def build_single_dataset(suffix: str, append_mode: bool = True) -> pd.DataFrame | None:
    config = get_dataset_config(suffix)
    benign_dir = config["benign_dir"]
    malware_dir = config["malware_dir"]
    output_csv = config["output_csv"]

    print(f"\n📂 [{suffix.upper()}] 가공 시작 -> {output_csv.name}")

    benign_files = collect_files(benign_dir)
    malware_files = collect_files(malware_dir)
    all_files = benign_files + malware_files

    if not all_files:
        print(f"  ⚠️ 가공할 파일이 없습니다. 폴더 확인 필요:\n     - {benign_dir}\n     - {malware_dir}")
        return None

    # 기존에 처리된 경로/파일명 로드
    existing_paths, existing_filenames = (
        load_existing_processed_paths(output_csv) if append_mode else (set(), set())
    )

    # 경로 정규화 비교 또는 파일명 기준 비교로 스킵 판별
    new_files = []
    for f in all_files:
        f_resolved = str(f.resolve()).lower()
        f_name = f.name.lower()
        
        # 절대경로나 파일명이 이미 존재하면 제외
        if f_resolved in existing_paths or f_name in existing_filenames:
            continue
        new_files.append(f)

    if not new_files:
        print(f"  ✨ 모든 파일({len(all_files)}개)이 이미 {output_csv.name}에 존재하여 건너뜁니다.")
        return pd.read_csv(output_csv)

    print(f"  총 {len(all_files)}개 중 신규 파일 {len(new_files)}개 특징 추출 진행 중...")
    
    # ... 이후 특징 추출 및 저장 로직 동일 ...

    # 전처리 엔진 호출
    features_list = preprocess_many(new_files)

    rows = []
    for file_path, features in zip(new_files, features_list):
        row = dict(features)
        row["filename"] = file_path.name
        row["filepath"] = str(file_path.resolve())

        # 라벨 결정 (benign / malware)
        if benign_dir.exists() and file_path.is_relative_to(benign_dir):
            row["label"] = "benign"
        elif malware_dir.exists() and file_path.is_relative_to(malware_dir):
            row["label"] = "malware"
        else:
            row["label"] = "unknown"

        rows.append(row)

    new_df = pd.DataFrame(rows)
    columns_order = ["label", "filename", "filepath"] + FEATURE_ORDER
    new_df = new_df[[col for col in columns_order if col in new_df.columns]]

    # CSV 디렉터리 생성 및 저장 (기존 내용 유지 + 신규 내용 덧붙이기)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if append_mode and output_csv.exists():
        old_df = pd.read_csv(output_csv)
        final_df = pd.concat([old_df, new_df], ignore_index=True).drop_duplicates(subset=["filepath"])
    else:
        final_df = new_df

    final_df.to_csv(output_csv, index=False, encoding="utf-8-sig")
    print(f"  ✅ [{output_csv.name}] 저장 완료! (총 {len(final_df)}개 샘플)")
    return final_df


def build_all_individual_datasets():
    """9개 데이터셋을 순회하며 각각 개별 CSV 파일로 생성/갱신"""
    print("🚀 9개 개별 데이터셋 일괄 가공 시작...")
    success_count = 0

    for suffix in DATASET_SUFFIXES:
        df = build_single_dataset(suffix)
        if df is not None:
            success_count += 1

    print("\n=======================================================")
    print(f"🎉 9개 데이터셋 중 {success_count}개 개별 CSV 생성/갱신 완료!")
    print(f"   저장 위치: {PROCESSED_DIR}")
    print("=======================================================")


def main():
    parser = argparse.ArgumentParser(description="9개 소스별 독립 데이터셋 가공 스크립트")
    parser.add_argument(
        "--target",
        type=str,
        choices=DATASET_SUFFIXES,
        help="특정 데이터셋 하나만 지정 가공 (예: napierone, webshell 등)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="9개 데이터셋을 순차적으로 모두 각각의 CSV로 가공",
    )

    args = parser.parse_args()

    if args.target:
        build_single_dataset(args.target)
    else:
        # 옵션 없이 실행하거나 --all 인 경우 9개 각각 순차 처리
        build_all_individual_datasets()


if __name__ == "__main__":
    main()