import os
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

# ---------------------------------------------------------
# 1. 설정 (원하는 정상 데이터 폴더 이름 지정)
# ---------------------------------------------------------
BENIGN_FOLDER_NAME = "benign_sources"  # 예: benign_custom, benign_samples 등 자유롭게 지정

# 프로젝트 루트 경로 설정
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parents[1] if CURRENT_DIR.name == "preprocessing" else CURRENT_DIR

# 출력 경로: data/raw/benign_원하는이름/
BENIGN_DIR = PROJECT_ROOT / "data" / "raw" / BENIGN_FOLDER_NAME


# ---------------------------------------------------------
# 2. 수집 함수 정의
# ---------------------------------------------------------
def download_wordpress_php(target_dir: Path):
    """WordPress 최신버전을 받아 정상 PHP 스크립트를 추출한다."""
    print("▶ [1/2] 정상 PHP 샘플 수집 중 (WordPress)...")
    wp_dir = target_dir / "wordpress_php"
    wp_dir.mkdir(parents=True, exist_ok=True)
    
    zip_path = wp_dir / "wordpress.zip"
    url = "https://wordpress.org/latest.zip"
    
    try:
        urllib.request.urlretrieve(url, zip_path)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(wp_dir)
            
        zip_path.unlink()  # 임시 zip 파일 삭제
        print(f"  [+] WordPress 정상 스크립트 추출 완료: {wp_dir}")
    except Exception as e:
        print(f"  [-] WordPress 다운로드 실패: {e}")


def download_arxiv_pdfs(target_dir: Path, count: int = 30):
    """arXiv API를 활용해 정상 학술 PDF 문서를 다운로드한다."""
    print(f"▶ [2/2] 정상 PDF 샘플 {count}개 수집 중 (arXiv)...")
    pdf_dir = target_dir / "arxiv_pdf"
    pdf_dir.mkdir(parents=True, exist_ok=True)
    
    api_url = f"http://export.arxiv.org/api/query?search_query=cat:cs.AI&start=0&max_results={count}"
    
    try:
        response = urllib.request.urlopen(api_url)
        xml_data = response.read()
        
        root = ET.fromstring(xml_data)
        ns = {'atom': 'http://www.w3.org/2005/Atom'}
        
        downloaded = 0
        for entry in root.findall('atom:entry', ns):
            id_text = entry.find('atom:id', ns).text
            paper_id = id_text.split('/abs/')[-1]
            pdf_url = f"https://arxiv.org/pdf/{paper_id}.pdf"
            
            save_path = pdf_dir / f"arxiv_{paper_id}.pdf"
            urllib.request.urlretrieve(pdf_url, save_path)
            downloaded += 1
            print(f"  [+] PDF 완료 ({downloaded}/{count}): {save_path.name}")
            
    except Exception as e:
        print(f"  [-] PDF 다운로드 중 오류 발생: {e}")


def main():
    BENIGN_DIR.mkdir(parents=True, exist_ok=True)
    print("=== 양질의 정상(Benign) 데이터 자동 수집 시작 ===")
    print(f"▶ 프로젝트 루트 경로 : {PROJECT_ROOT}")
    print(f"▶ 저장 디렉터리 경로 : {BENIGN_DIR}\n")
    
    # 1. 정상 PHP 수집
    download_wordpress_php(BENIGN_DIR)
    
    # 2. 정상 PDF 수집 (원하는 수량으로 조절 가능)
    download_arxiv_pdfs(BENIGN_DIR, count=1200)
    
    print("\n=========================================")
    print(f"🎉 모든 수집 완료! (저장 위치: {BENIGN_DIR})")
    print("💡 필요 시 로컬 PC의 System32(.exe)나 이미지(.jpg) 파일도 이 폴더에 복사해 넣으시면 됩니다.")


if __name__ == "__main__":
    main()