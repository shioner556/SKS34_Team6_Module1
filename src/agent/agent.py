"""3단계: OpenAI Agent 분석
1~2단계 결과(features, prediction)를 받아 위험도 근거, 관련 CVE,
대응 가이드를 구조화된 리포트(JSON)로 생성한다.
"""
import os
import json
from openai import OpenAI
from dotenv import load_dotenv

from .tools import TOOLS, TOOL_FUNCTIONS

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = """너는 웹 서버 파일 업로드 취약점을 전문으로 분석하는 모의해킹 전문가다.
1단계 정적분석 결과와 2단계 ML 위험도 점수를 근거로,
시스템/웹서버 관점에서의 영향도와 대응 방안을 제시해야 한다.
반드시 제공된 tool을 사용해 관련 CVE를 조회하고, 근거 없는 추측은 하지 마라.

위험도 판단 기준:
- 90% 이상: 상
- 40% ~ 89%: 중
- 40% 미만: 하
"""

REPORT_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
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
}


def analyze_with_agent(features: dict, prediction: dict) -> dict:
    """3단계: OpenAI Agent 분석"""
    print("[3단계] Agent 분석 시작")

    user_msg = f"""[1단계 정적분석 결과]
{json.dumps(features, ensure_ascii=False, indent=2)}

[2단계 ML 판단]
{json.dumps(prediction, ensure_ascii=False, indent=2)}

위 정보를 바탕으로 위험도, 판단 근거, 관련 CVE, 대응 가이드를 정리해줘."""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_msg}
    ]

    # 1차 호출: tool 사용 여부 판단
    resp = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        tools=TOOLS
    )
    msg = resp.choices[0].message

    if msg.tool_calls:
        messages.append(msg)
        for tc in msg.tool_calls:
            fn = TOOL_FUNCTIONS[tc.function.name]
            args = json.loads(tc.function.arguments)
            try:
                result = fn(**args)
            except Exception as e:
                result = {"error": str(e)}
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(result, ensure_ascii=False)
            })

    # 2차 호출: 구조화된 최종 리포트
    final = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        response_format=REPORT_SCHEMA
    )

    return json.loads(final.choices[0].message.content)
