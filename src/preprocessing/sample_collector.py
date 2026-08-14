"""
collector.py - 다중 소스 데이터 수집 및 다운로드 통합 모듈

지원 데이터 수집 소스:
1. bazaar    : MalwareBazaar 악성코드 샘플 수집 (API Key 필요)
2. arxiv     : arXiv 학술 논문 정상 PDF 수집
3. wordpress : WordPress 공식 배포판 정상 PHP 스크립트 수집
4. images    : Wikimedia, MET Museum, Library of Congress 정상 이미지 수집

실행 방법:
    # 전체 소스 일괄 수집
    python src/preprocessing/collector.py --all

    # 특정 소스만 선택 수집
    python src/preprocessing/collector.py --source bazaar
    python src/preprocessing/collector.py --source arxiv
    python src/preprocessing/collector.py --source wordpress
    python src/preprocessing/collector.py --source images
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

import re
from urllib.parse import unquote, urlparse

# .env 환경변수 로드
load_dotenv()

# 프로젝트 루트 경로 (src/preprocessing/collector.py 기준 상위 2단계)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"


# =====================================================================
# 1. MalwareBazaar 악성코드 수집기
# =====================================================================
def collect_malwarebazaar(limit_per_type: int = 30) -> None:
    """MalwareBazaar API를 통해 다양한 확장자의 악성코드 샘플을 수집 및 압축 해제"""
    try:
        import pyzipper
    except ImportError:
        print("  ❌ [Bazaar] pyzipper 패키지가 필요합니다: pip install pyzipper")
        return

    api_key = os.getenv("MALWAREBAZAAR_API_KEY")
    if not api_key:
        print("  ⚠️ [Bazaar] .env에 MALWAREBAZAAR_API_KEY가 설정되어 있지 않아 건너뜁니다.")
        return

    output_dir = RAW_DATA_DIR / "malware_bazaar"
    output_dir.mkdir(parents=True, exist_ok=True)
    api_url = "https://mb-api.abuse.ch/api/v1/"

    target_types = [
        "exe", "dll", "elf", "pdf", "doc", "docx", "xls", "xlsx",
        "js", "vbs", "ps1", "bat", "php", "zip", "7z"
    ]

    print(f"\n🕷️ [MalwareBazaar] 악성코드 수집 시작 -> {output_dir.name}")
    headers = {"API-KEY": api_key}

    for ftype in target_types:
        print(f"  ▶ [{ftype.upper()}] 해시 목록 조회 중...")
        data = {"query": "get_file_type", "file_type": ftype, "limit": limit_per_type}
        try:
            res = requests.post(api_url, data=data, headers=headers, timeout=15)
            res_json = res.json()
            if res_json.get("query_status") != "ok":
                continue

            for item in res_json.get("data", []):
                sha256_hash = item.get("sha256_hash")
                file_name = item.get("file_name") or f"{sha256_hash}.{ftype}"
                
                # 중복 다운로드 검사 (이미 파일이 있으면 스킵)
                dest_file = output_dir / f"{sha256_hash}_{file_name}"
                if dest_file.exists() and dest_file.stat().st_size > 0:
                    continue

                # 다운로드 요청
                dl_res = requests.post(api_url, data={"query": "get_file", "sha256_hash": sha256_hash}, headers=headers, timeout=30)
                if dl_res.status_code == 200:
                    zip_path = output_dir / f"{sha256_hash}.zip"
                    zip_path.write_bytes(dl_res.content)
                    try:
                        with pyzipper.AESZipFile(zip_path) as zf:
                            zf.pwd = b"infected"
                            zf.extractall(output_dir)
                        print(f"    [+] 추출 완료: {dest_file.name[:25]}...")
                    except Exception:
                        pass
                    finally:
                        if zip_path.exists():
                            zip_path.unlink()
                time.sleep(0.3)
        except Exception as e:
            print(f"    ⚠️ [{ftype}] 수집 중 에러: {e}")


# =====================================================================
# 2. arXiv 정상 PDF 논문 수집기
# =====================================================================
def collect_arxiv_pdf(count: int = 50) -> None:
    """arXiv API를 통해 정상 학술 논문 PDF 수집"""
    output_dir = RAW_DATA_DIR / "benign_arxiv_pdf"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n📄 [arXiv] 정상 PDF 논문 수집 시작 -> {output_dir.name}")
    api_url = f"http://export.arxiv.org/api/query?search_query=cat:cs.AI&start=0&max_results={count}"

    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as response:
            xml_data = response.read()

        root = ET.fromstring(xml_data)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        downloaded = 0

        for entry in root.findall("atom:entry", ns):
            id_text = entry.find("atom:id", ns).text
            paper_id = id_text.split("/abs/")[-1].replace("/", "_")
            save_path = output_dir / f"arxiv_{paper_id}.pdf"

            # 이미 존재하면 스킵
            if save_path.exists() and save_path.stat().st_size > 0:
                continue

            pdf_url = f"https://arxiv.org/pdf/{paper_id}.pdf"
            pdf_req = urllib.request.Request(pdf_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(pdf_req, timeout=30) as pdf_res, open(save_path, "wb") as f:
                f.write(pdf_res.read())

            downloaded += 1
            print(f"  [+] PDF 다운로드 완료 ({downloaded}): {save_path.name}")
            time.sleep(0.5)

        print(f"  ✅ [arXiv] 총 {downloaded}개 신규 PDF 수집 완료")
    except Exception as e:
        print(f"  ⚠️ [arXiv] 수집 중 에러 발생: {e}")


# =====================================================================
# 3. WordPress 정상 PHP 스크립트 수집기
# =====================================================================
def collect_wordpress_php() -> None:
    """WordPress 최신 버전을 다운로드하여 정상 PHP 파일들을 추출"""
    output_dir = RAW_DATA_DIR / "benign_wordpress_php"
    output_dir.mkdir(parents=True, exist_ok=True)

    # 이미 PHP 파일들이 존재하면 스킵
    existing_php = list(output_dir.rglob("*.php"))
    if len(existing_php) > 50:
        print(f"\n🌐 [WordPress] 이미 {len(existing_php)}개의 PHP 파일이 존재하여 건너뜁니다.")
        return

    print(f"\n🌐 [WordPress] 정상 PHP 샘플 수집 시작 -> {output_dir.name}")
    zip_path = output_dir / "wordpress.zip"
    url = "https://wordpress.org/latest.zip"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as res, open(zip_path, "wb") as f:
            f.write(res.read())

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            php_files = [f for f in zip_ref.namelist() if f.endswith(".php")]
            for file in php_files:
                zip_ref.extract(file, output_dir)

        if zip_path.exists():
            zip_path.unlink()
        print(f"  ✅ [WordPress] PHP 파일 {len(php_files)}개 추출 완료")
    except Exception as e:
        print(f"  ⚠️ [WordPress] 다운로드 중 에러 발생: {e}")


# =====================================================================
# 4. Wikimedia / MET / LOC 정상 이미지 수집기 (특수문자 및 물음표 제거 패치)
# =====================================================================
def sanitize_filename(name: str) -> str:
    """윈도우 파일명에 사용할 수 없는 특수문자 치환"""
    return re.sub(r'[\\/*?:"<>|]', "_", name)


def collect_benign_images(limit_per_format: int = 50) -> None:
    """Wikimedia Commons API를 통해 포맷별 정상 이미지 안전하게 수집"""
    output_dir = RAW_DATA_DIR / "benign_image_anomaly"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n🖼️ [Images] 정상 이미지 샘플 수집 시작 -> {output_dir.name}")
    formats = ["jpg", "png", "gif", "bmp", "webp"]

    headers = {"User-Agent": "SKS34-Team6-ImageDataset/1.0 (academic research)"}
    
    for fmt in formats:
        fmt_dir = output_dir / fmt
        fmt_dir.mkdir(parents=True, exist_ok=True)
        existing_count = len(list(fmt_dir.glob(f"*.{fmt}")))

        if existing_count >= limit_per_format:
            print(f"  ✨ [{fmt.upper()}] 이미 {existing_count}개의 이미지가 있어 건너뜁니다.")
            continue

        print(f"  ▶ [{fmt.upper()}] 이미지 수집 중...")
        api_url = "https://commons.wikimedia.org/w/api.php"
        params = {
            "action": "query",
            "format": "json",
            "generator": "search",
            "gsrsearch": f"filetype:bitmap {fmt}",
            "gsrnamespace": "6",
            "gsrlimit": str(limit_per_format),
            "prop": "imageinfo",
            "iiprop": "url|mime",
        }
        
        try:
            res = requests.get(api_url, params=params, headers=headers, timeout=15)
            pages = res.json().get("query", {}).get("pages", {})
            downloaded = 0
            
            for pid, pdata in pages.items():
                img_infos = pdata.get("imageinfo", [])
                if not img_infos:
                    continue
                img_url = img_infos[0].get("url")
                if not img_url:
                    continue

                # 핵심 해결: URL에서 물음표(?) 및 쿼리 스트링을 분리하고 순수 파일명만 추출
                parsed_url = urlparse(img_url)
                raw_filename = Path(parsed_url.path).name  # ?utm_source... 제거됨
                clean_filename = sanitize_filename(unquote(raw_filename)) # URL 인코딩 해제 및 특수문자 제거

                save_path = fmt_dir / clean_filename
                
                # 이미 존재하면 스킵
                if save_path.exists() and save_path.stat().st_size > 0:
                    continue

                img_res = requests.get(img_url, headers=headers, timeout=20)
                if img_res.status_code == 200:
                    save_path.write_bytes(img_res.content)
                    downloaded += 1
                    print(f"    [+] {fmt.upper()} 저장: {save_path.name[:30]}...")

                time.sleep(0.3)
                
        except Exception as e:
            print(f"    ⚠️ [{fmt}] 수집 중 에러: {e}")

    print(f"  ✅ [Images] 정상 이미지 수집 작업 완료 -> {output_dir}")


# =====================================================================
# 메인 CLI 인터페이스
# =====================================================================
def main():
    parser = argparse.ArgumentParser(description="통합 데이터 수집기 (Collector)")
    parser.add_argument(
        "--source",
        type=str,
        choices=["bazaar", "arxiv", "wordpress", "images"],
        help="특정 데이터 소스만 지정하여 수집 (예: bazaar, arxiv, wordpress, images)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="모든 데이터 소스를 순차적으로 일괄 수집",
    )

    args = parser.parse_args()

    if args.source == "bazaar":
        collect_malwarebazaar()
    elif args.source == "arxiv":
        collect_arxiv_pdf()
    elif args.source == "wordpress":
        collect_wordpress_php()
    elif args.source == "images":
        collect_benign_images()
    else:
        # 기본값: 전체 순차 실행
        print("🚀 모든 데이터 소스 수집을 시작합니다...")
        collect_wordpress_php()
        collect_arxiv_pdf()
        collect_benign_images()
        collect_malwarebazaar()
        print("\n🎉 모든 데이터 수집 작업이 완료되었습니다!")


if __name__ == "__main__":
    main()