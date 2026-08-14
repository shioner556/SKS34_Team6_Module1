# 1단계 및 UI 팀원은 본인 코드에서 아래와 같이 간단히 불러와서 사용하세요

from src.ml.predict import predict_malware_risk, predict_malware_risk_json

# 1단계에서 생성된 ml_features 딕셔너리 
ml_features = {
    ...
}

# Python Dict 결과가 필요할 때 (Streamlit 화면 표시용)
result_dict = predict_malware_risk(ml_features)
print(result_dict["malware_probability"]) # '92.5%'

# JSON 문자열 결과가 필요할 때 (OpenAI Agent 전달용)
result_json = predict_malware_risk_json(ml_features)

-------------------------------------------------------------------------

3단계 OpenAI Agent(Custom Tool)에서 사용할 ML 위험도 추론 모듈 구현이 완료되었습니다

Agent 툴 연동 시 아래 안내를 참고하셔서 import하여 사용하시면 됩니다!

-------------------------------------------------------------------------

### ML 위험도 추론 툴 연동 안내

1. **Import 경로**
   ```python
   from src.ml.predict import predict_malware_risk_json