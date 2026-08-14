"""CVE 벡터스토어 설정 스크립트
==============================================

■ 이 파일이 하는 일
  data/cve/ 폴더에 있는 CVE 파일(JSON/PDF/TXT)을 OpenAI 벡터스토어에 업로드한다.
  벡터스토어는 3단계 Agent가 CVE를 의미 기반으로 검색(file_search)할 때 사용한다.

■ 누가 실행하나?
  팀장(또는 담당자)이 실행한다. 팀원 전체가 실행할 필요는 없다.

■ 언제 실행하나?
  1. 처음 프로젝트 세팅할 때 1회 실행
  2. data/cve/ 안의 CVE 파일을 추가/수정했을 때 재실행 (기존 ID 유지)

■ 실행 방법 (프로젝트 루트에서)
  python src/agent/setup_vectorstore.py

■ 실행 결과
  - 최초 실행: 벡터스토어 생성 후 VECTOR_STORE_ID를 .env에 자동 저장
  - 재실행: 기존 파일 삭제 후 재업로드 (VECTOR_STORE_ID는 변경되지 않음)

■ 팀원들이 해야 할 일
  팀장이 실행 후 출력된 VECTOR_STORE_ID를 각자 .env에 추가하면 된다.
  예) VECTOR_STORE_ID=vs_xxxxxxxxxxxxxxxxxxxxxxxx

■ 주의사항
  - 실행 전 .env에 OPENAI_API_KEY가 설정되어 있어야 한다.
  - data/cve/ 폴더에 파일이 1개 이상 있어야 한다.
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv, set_key
from openai import OpenAI

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
# src/agent/ 기준으로 프로젝트 루트는 두 단계 위
PROJECT_ROOT = Path(__file__).parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "cve"
ENV_PATH = PROJECT_ROOT / ".env"


def _get_files() -> list[Path]:
    files = [p for p in DATA_DIR.glob("*") if p.suffix in [".json", ".pdf", ".txt"]]
    if not files:
        print(f"[오류] {DATA_DIR}에 파일이 없습니다.")
        sys.exit(1)
    return files


def _upload_files(vs_id: str, files: list[Path]):
    print(f"{len(files)}개 파일을 벡터스토어에 업로드 중...")
    file_streams = [open(f, "rb") for f in files]
    client.vector_stores.file_batches.upload_and_poll(
        vector_store_id=vs_id,
        files=file_streams
    )
    for f in file_streams:
        f.close()


def run():
    vs_id = os.getenv("VECTOR_STORE_ID")
    files = _get_files()

    if not vs_id:
        print("벡터스토어가 없습니다. 새로 생성합니다...")
        vs = client.vector_stores.create(name="CVE Database")
        vs_id = vs.id
        _upload_files(vs_id, files)
        set_key(str(ENV_PATH), "VECTOR_STORE_ID", vs_id)
        print(f"\n완료! VECTOR_STORE_ID: {vs_id}")
        print("위 ID를 팀원들의 .env에 추가해주세요.")
    else:
        print(f"기존 벡터스토어 파일을 교체합니다... (ID: {vs_id})")
        existing_files = client.vector_stores.files.list(vector_store_id=vs_id)
        for vf in existing_files.data:
            client.vector_stores.files.delete(vector_store_id=vs_id, file_id=vf.id)
        print(f"  기존 {len(existing_files.data)}개 파일 삭제 완료")
        _upload_files(vs_id, files)
        print(f"\n완료! 벡터스토어 업데이트됨 (ID: {vs_id})")
        print("팀원들은 .env를 바꿀 필요 없습니다.")


if __name__ == "__main__":
    run()
