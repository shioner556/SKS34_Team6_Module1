import os
from collections import Counter
from pathlib import Path


def count_extensions_by_group(raw_dir: Path):
    if not raw_dir.exists():
        print(f"[!] 대상 디렉터리가 존재하지 않습니다: {raw_dir}")
        return

    # 그룹별 전체 카운터
    benign_total = Counter()
    malware_total = Counter()

    # 폴더별 개별 카운터
    benign_folder_counts = {}
    malware_folder_counts = {}

    # data/raw 하위 디렉터리 탐색
    for folder in sorted(raw_dir.iterdir()):
        if not folder.is_dir():
            continue

        folder_name_lower = folder.name.lower()

        # benign 그룹 판단 (benign, benign_*)
        if folder_name_lower == "benign" or folder_name_lower.startswith("benign_"):
            group = "benign"
        # malware 그룹 판단 (malware, malware_*)
        elif folder_name_lower == "malware" or folder_name_lower.startswith("malware_"):
            group = "malware"
        else:
            continue

        folder_counter = Counter()

        # 하위 모든 파일 재귀 탐색 (rglob)
        for file_path in folder.rglob("*"):
            if file_path.is_file():
                ext = file_path.suffix.lower()
                if not ext:
                    ext = "[확장자 없음]"
                folder_counter[ext] += 1

        # 그룹별 데이터 저장
        if group == "benign":
            benign_folder_counts[folder.name] = folder_counter
            benign_total.update(folder_counter)
        else:
            malware_folder_counts[folder.name] = folder_counter
            malware_total.update(folder_counter)

    # 집계 결과 출력 함수
    def print_summary(group_title: str, folder_counts: dict, total_counter: Counter):
        print("=" * 65)
        print(f"📊 [{group_title}] 파일 확장자 분포 통계")
        print("=" * 65)

        if not folder_counts:
            print("  해당 그룹에 해당하는 폴더가 없습니다.\n")
            return

        # 1. 폴더별 세부 내역 출력
        print("\n📂 [1] 폴더별 확장자 세부 내역")
        print("-" * 65)
        for folder_name, counter in folder_counts.items():
            folder_file_sum = sum(counter.values())
            print(f"▶ 폴더명: {folder_name} (총 {folder_file_sum:,}개 파일)")
            print(f"   {'확장자':<15} {'개수':>10}")
            print("   " + "-" * 28)
            for ext, count in counter.most_common():
                print(f"   {ext:<15} {count:>10,}개")
            print()

        # 2. 그룹 통합 확장자 내역 출력
        grand_total = sum(total_counter.values())
        print(f"📈 [2] [{group_title}] 통합 확장자 총계 (총 {grand_total:,}개 파일)")
        print("-" * 65)
        print(f"   {'확장자':<15} {'개수':>10} {'점유율':>12}")
        print("   " + "-" * 40)
        for ext, count in total_counter.most_common():
            ratio = (count / grand_total * 100) if grand_total > 0 else 0
            print(f"   {ext:<15} {count:>10,}개 ({ratio:>5.1f}%)")
        print("\n")

    # 정상 및 악성 결과 출력
    print_summary("BENIGN (정상 파일)", benign_folder_counts, benign_total)
    print_summary("MALWARE (악성 파일)", malware_folder_counts, malware_total)


if __name__ == "__main__":
    # 프로젝트 루트 경로 자동 계산 (src/preprocessing/ 아래에 있거나 루트에 있어도 동작)
    CURRENT_DIR = Path(__file__).resolve().parent
    PROJECT_ROOT = CURRENT_DIR.parents[1] if CURRENT_DIR.name == "preprocessing" else CURRENT_DIR
    RAW_DIR = PROJECT_ROOT / "data" / "raw"

    print(f"🔍 탐색 경로: {RAW_DIR}\n")
    count_extensions_by_group(RAW_DIR)