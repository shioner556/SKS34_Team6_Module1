"""CVE 벡터스토어 최초 설정 스크립트
최초 1회만 실행.
생성된 VECTOR_STORE_ID를 .env에 저장하고 팀원들에게 공유한다.
"""
import os
from pathlib import Path
from dotenv import load_dotenv, set_key
from openai import OpenAI

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
DATA_DIR = Path(__file__).parent / "data" / "cve"
ENV_PATH = Path(__file__).parent / ".env"


def setup():
    existing_id = os.getenv("VECTOR_STORE_ID")
    if existing_id:
        print(f"이미 벡터스토어 ID가 있습니다: {existing_id}")
        print("새로 만들려면 .env에서 VECTOR_STORE_ID를 삭제 후 다시 실행하세요.")
        return

    files = [p for p in DATA_DIR.glob("*") if p.suffix in [".json", ".pdf", ".txt"]]
    if not files:
        print(f"[오류] {DATA_DIR}에 파일이 없습니다.")
        return

    print(f"{len(files)}개 파일을 벡터스토어에 업로드 중...")
    vs = client.vector_stores.create(name="CVE Database")
    file_streams = [open(f, "rb") for f in files]
    client.vector_stores.file_batches.upload_and_poll(
        vector_store_id=vs.id,
        files=file_streams
    )
    for f in file_streams:
        f.close()

    set_key(str(ENV_PATH), "VECTOR_STORE_ID", vs.id)
    print(f"\n완료! VECTOR_STORE_ID: {vs.id}")
    print("위 ID를 팀원들의 .env에 추가해주세요.")


if __name__ == "__main__":
    setup()
