"""3단계 agent가 사용하는 tool 정의 모음"""
import requests


def get_cve_info(keyword: str):
    """NVD API로 키워드 관련 CVE를 검색한다 (예: 'PHP webshell', 'double extension upload')"""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    resp = requests.get(url, params={"keywordSearch": keyword, "resultsPerPage": 5}, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    return [
        {
            "id": item["cve"]["id"],
            "desc": item["cve"]["descriptions"][0]["value"]
        }
        for item in data.get("vulnerabilities", [])
    ]

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
