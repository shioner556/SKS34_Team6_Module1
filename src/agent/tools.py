"""3단계 agent가 사용하는 tool 정의 모음"""
import os
import time
import requests

NVD_API_KEY = os.getenv("NVD_API_KEY")  # 있으면 30초당 5회 -> 50회로 제한 완화됨


def get_cve_info(keyword: str, max_retries: int = 2):
    """NVD API로 키워드 관련 CVE를 검색한다 (예: 'PHP webshell', 'double extension upload').
    실패(레이트리밋/타임아웃 등) 시 예외를 던지지 않고 빈 리스트를 반환한다.
    -> agent.py 쪽에서 '설명 못 찾으면 해당 CVE 제외' 규칙을 따르게 하기 위함."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    for attempt in range(max_retries + 1):
        try:
            resp = requests.get(
                url,
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                headers=headers,
                timeout=10
            )
            if resp.status_code == 429:
                # 레이트리밋: API 키 없으면 30초당 5회 제한
                wait = 6 * (attempt + 1)
                print(f"[NVD] 429 rate limit, {wait}초 대기 후 재시도 ({attempt + 1}/{max_retries})")
                time.sleep(wait)
                continue

            resp.raise_for_status()
            data = resp.json()
            return [
                {
                    "id": item["cve"]["id"],
                    "desc": item["cve"]["descriptions"][0]["value"]
                }
                for item in data.get("vulnerabilities", [])
                if item.get("cve", {}).get("descriptions")
            ]

        except requests.exceptions.RequestException as e:
            print(f"[NVD] 조회 실패 ({keyword}): {e}")
            if attempt == max_retries:
                return []
            time.sleep(2)

    return []

# OpenAI function-calling에 넘길 tool 스펙
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_cve_info",
            "description": "키워드로 관련 CVE를 검색한다",
            "parameters": {
                "type": "object",
                "properties": {"keyword": {"type": "string"}},
                "required": ["keyword"]
            }
        }
    }
]

# tool 이름 -> 실제 실행 함수 매핑 (openai_agent.py에서 dispatch용으로 사용)
TOOL_FUNCTIONS = {
    "get_cve_info": get_cve_info,
}