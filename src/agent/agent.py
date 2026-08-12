"""3단계: OpenAI Agent 분석
1~2단계 결과(features, prediction)를 받아 위험도 근거, 관련 CVE,
대응 가이드를 구조화된 리포트(JSON)로 생성한다.

Responses API + OpenAI 벡터스토어 방식:
- data/ 폴더의 CVE 파일(JSON/PDF/TXT)을 벡터스토어에 업로드해 파일 서치에 활용
- 벡터스토어가 없거나 실패하면 웹서치(NVD API)만 사용
"""
import os
import json
from pathlib import Path
from openai import OpenAI
from dotenv import load_dotenv

from .tools import TOOLS, TOOL_FUNCTIONS

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MODEL = "gpt-4o-mini"

DATA_DIR = Path(__file__).parent.parent.parent / "data" / "cve"

SYSTEM_PROMPT = """너는 웹 서버 파일 업로드 취약점을 전문으로 분석하는 보안 탐지견이다.
1단계 정적분석 결과와 2단계 ML 위험도 점수를 근거로,
시스템/웹서버 관점에서의 영향도와 대응 방안을 제시해야 한다.
반드시 제공된 tool을 사용해 관련 CVE를 조회하고, 근거 없는 추측은 하지 마라.

말투 규칙 (반드시 지켜라):
- summary, evidence, recommended_actions 모든 텍스트 필드에서 반드시 강아지 말투를 써야 한다.
- 예: "멍! 위험한 냄새가 납니다!", "왈왈! 즉시 조치가 필요합니다!", "컹컹! 수상한 확장자를 탐지했습니다!"
- 분석 내용은 정확하게, 표현은 반드시 강아지처럼.

위험도 판단 기준:
- 90% 이상: 상
- 40% ~ 89%: 중
- 40% 미만: 하
"""

REPORT_SCHEMA = {
    "type": "json_schema",
    "name": "risk_report",
    "schema": {
        "type": "object",
        "properties": {
            "risk_level": {"type": "string", "enum": ["상", "중", "하"]},
            "summary": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"}},
            "related_cve": {"type": "array", "items": {"type": "string"}},
            "recommended_actions": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["risk_level", "summary", "evidence", "related_cve", "recommended_actions"],
        "additionalProperties": False
    },
    "strict": True
}

_vector_store_id = None


def _get_or_create_vector_store() -> str | None:
    """data/ 폴더의 파일들을 OpenAI 벡터스토어에 업로드하고 ID를 반환한다.
    이미 생성된 경우 캐시된 ID를 반환한다. 파일이 없으면 None을 반환한다.
    """
    global _vector_store_id
    if _vector_store_id:
        return _vector_store_id

    if not DATA_DIR.exists():
        return None

    files = [p for p in DATA_DIR.glob("*") if p.suffix in [".json", ".pdf", ".txt"]]
    if not files:
        return None

    try:
        vs = client.vector_stores.create(name="CVE Database")
        file_streams = [open(f, "rb") for f in files]
        client.vector_stores.file_batches.upload_and_poll(
            vector_store_id=vs.id,
            files=file_streams
        )
        for f in file_streams:
            f.close()
        _vector_store_id = vs.id
        print(f"[벡터스토어] {len(files)}개 파일 업로드 완료 (ID: {vs.id})")
        return _vector_store_id
    except Exception as e:
        print(f"[경고] 벡터스토어 설정 실패, 웹서치만 사용합니다: {e}")
        return None


def _build_tools(vs_id: str | None) -> list:
    """Responses API용 tool 목록을 생성한다.
    벡터스토어 file_search + 함수 tool(NVD 웹서치) 포함.
    TOOLS는 Chat Completions 형식이므로 Responses API 형식으로 변환한다.
    """
    tools = []

    if vs_id:
        tools.append({"type": "file_search", "vector_store_ids": [vs_id]})

    for tool in TOOLS:
        fn = tool["function"]
        tools.append({
            "type": "function",
            "name": fn["name"],
            "description": fn["description"],
            "parameters": fn["parameters"]
        })

    return tools


def analyze_with_agent(features: dict, prediction: dict) -> dict:
    """3단계: OpenAI Responses API + 벡터스토어로 종합 분석 후 리포트 반환"""

    vs_id = _get_or_create_vector_store()
    tools = _build_tools(vs_id)

    user_msg = f"""[1단계 정적분석 결과]
{json.dumps(features, ensure_ascii=False, indent=2)}

[2단계 ML 판단]
{json.dumps(prediction, ensure_ascii=False, indent=2)}

위 정보를 바탕으로 위험도, 판단 근거, 관련 CVE, 대응 가이드를 정리해줘."""

    # 1차 호출: file_search(자동) + 함수 tool 사용 여부 판단
    try:
        response = client.responses.create(
            model=MODEL,
            instructions=SYSTEM_PROMPT,
            input=user_msg,
            tools=tools
        )
    except Exception as e:
        print(f"[오류] OpenAI API 호출 실패 (1차): {e}")
        raise

    # 함수 tool call 처리 (file_search는 OpenAI가 자동으로 처리)
    function_outputs = []
    for item in response.output:
        if item.type == "function_call":
            fn = TOOL_FUNCTIONS.get(item.name)
            args = json.loads(item.arguments)
            try:
                result = fn(**args)
            except Exception as e:
                result = {"error": str(e)}
            function_outputs.append({
                "type": "function_call_output",
                "call_id": item.call_id,
                "output": json.dumps(result, ensure_ascii=False)
            })

    # 2차 호출: 구조화된 최종 리포트 생성
    final_input = function_outputs if function_outputs else "위 분석을 바탕으로 최종 리포트를 작성해줘."
    try:
        final = client.responses.create(
            model=MODEL,
            instructions=SYSTEM_PROMPT,
            previous_response_id=response.id,
            input=final_input,
            text={"format": REPORT_SCHEMA}
        )
    except Exception as e:
        print(f"[오류] OpenAI API 호출 실패 (2차): {e}")
        raise

    for item in final.output:
        if item.type == "message":
            for content in item.content:
                if content.type == "output_text":
                    return json.loads(content.text)

    raise RuntimeError("[오류] 리포트 생성에 실패했습니다.")
