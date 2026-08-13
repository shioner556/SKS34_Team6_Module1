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

CVE 조회 규칙 (반드시 지켜라):
- 반드시 file_search로 내부 CVE 데이터베이스를 먼저 조회하라.
- 내부에서 충분한 CVE를 찾지 못한 경우에만 get_cve_info로 웹서치를 보조로 사용하라.
- 근거 없는 추측은 하지 마라.

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


def _get_vector_store() -> str | None:
    """.env의 VECTOR_STORE_ID를 읽어 반환한다.
    ID가 없으면 None을 반환하고 웹서치만 사용한다.
    벡터스토어 생성은 setup_vectorstore.py를 실행할 것.
    """
    global _vector_store_id
    if _vector_store_id:
        return _vector_store_id

    saved_id = os.getenv("VECTOR_STORE_ID")
    if saved_id:
        _vector_store_id = saved_id
        print(f"[벡터스토어] ID 로드 (ID: {saved_id})")
        return _vector_store_id

    print("[경고] VECTOR_STORE_ID가 .env에 없습니다. setup_vectorstore.py를 먼저 실행하세요. 웹서치만 사용합니다.")
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


def _fallback_report(prediction: dict, error_msg: str) -> dict:
    """3단계 분석 실패 시 반환할 기본 리포트 (동일 스키마 유지, 예외를 밖으로 던지지 않기 위함)."""
    risk_level = prediction.get("risk_level")
    if risk_level not in ["상", "중", "하"]:
        risk_level = "중"

    return {
        "risk_level": risk_level,
        "summary": f"멍... 분석 중 오류가 발생해서 자동 리포트를 만들지 못했습니다. (오류: {error_msg})",
        "evidence": ["3단계 AI 분석 실패 — 2단계 ML 판단 결과만 참고하세요."],
        "related_cve": [],
        "recommended_actions": ["관리자에게 문의하거나 재시도해주세요."]
    }


def analyze_with_agent(features: dict, prediction: dict, model: str = MODEL) -> dict:
    """3단계: OpenAI Responses API + 벡터스토어로 종합 분석 후 리포트 반환.
    model: 사용할 OpenAI 모델 (기본값: gpt-4o-mini). UI에서 모델 선택 시 전달.
    실패 시에도 동일 스키마의 fallback 리포트를 반환한다 (예외를 밖으로 던지지 않음)."""

    try:
        vs_id = _get_vector_store()
        tools = _build_tools(vs_id)

        user_msg = f"""[1단계 정적분석 결과]
{json.dumps(features, ensure_ascii=False, indent=2)}

[2단계 ML 판단]
{json.dumps(prediction, ensure_ascii=False, indent=2)}

위 정보를 바탕으로 위험도, 판단 근거, 관련 CVE, 대응 가이드를 정리해줘."""

        # 1차 호출: file_search(자동) + 함수 tool 사용 여부 판단
        response = client.responses.create(
            model=model,
            instructions=SYSTEM_PROMPT,
            input=user_msg,
            tools=tools
        )

        # tool 호출 로그 출력 및 함수 tool call 처리
        function_outputs = []
        for item in response.output:
            if item.type == "file_search_call":
                print(f"[tool] file_search 호출됨 (쿼리: {getattr(item, 'queries', '-')})")
            elif item.type == "function_call":
                print(f"[tool] {item.name} 호출됨 (인자: {item.arguments})")
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
        final = client.responses.create(
            model=model,
            instructions=SYSTEM_PROMPT,
            previous_response_id=response.id,
            input=final_input,
            text={"format": REPORT_SCHEMA}
        )

        for item in final.output:
            if item.type == "message":
                for content in item.content:
                    if content.type == "output_text":
                        return json.loads(content.text)

        raise RuntimeError("리포트 생성 실패: 최종 응답에 message가 없음")

    except Exception as e:
        print(f"[오류] 3단계 분석 실패: {e}")
        return _fallback_report(prediction, str(e))