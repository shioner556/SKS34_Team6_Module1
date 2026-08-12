# 1단계 전처리(preprocess) 결과 피처를 입력받아 학습된 모델 파일(.pkl)을 이용해 악성 확률을 계산하는 코드

import os
import joblib
import pandas as pd
import json

# 현재 파일(predict.py) 위치 기준으로 프로젝트 루트(최상위) 폴더 계산
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# models/random_forest.pkl 경로 조합
MODEL_PATH = os.path.join(BASE_DIR, "models", "random_forest.pkl")

# 1단계 정적 분석(preprocess) 결과의 수치형 피처 
FEATURE_COLUMNS = [
    'file_size', 'filename_length', 'extension_count', 'has_double_extension',
    'has_uppercase_extension', 'has_unicode_control_char', 'special_char_ratio',
    'is_executable_extension', 'is_script_extension', 'is_macro_document',
    'is_archive_extension', 'is_unknown_extension', 'magic_bytes_known',
    'magic_bytes_valid', 'extension_mime_mismatch', 'claimed_mime_mismatch',
    'embedded_file_signature_count', 'byte_entropy', 'header_entropy',
    'printable_ratio', 'null_byte_ratio', 'unique_byte_count', 'url_count',
    'ip_address_count', 'base64_candidate_count', 'suspicious_command_count',
    'execution_api_count', 'network_api_count', 'obfuscation_pattern_count',
    'suspicious_string_count', 'archive_entry_count', 'executable_entry_count',
    'script_entry_count', 'archive_depth', 'compression_ratio', 'archive_bomb_suspected'
]

def load_model():
    """
    pkl 모델 파일 로드 (파일이 없을 경우 None 반환)
    """
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"[ML Module Error] 모델 로딩 실패: {e}")
            return None
    return None

# 모듈 로드 시 모델 1회 캐싱
_model_instance = load_model()


def predict_malware_risk(ml_features: dict) -> dict:
    # 1. 입력 피처 데이터를 DataFrame 1줄 형태로 변환
    df_input = pd.DataFrame([ml_features])

    # -------------------------------------------------------------
    # 💡 핵심: 팀원분의 get_dummies 방식과 피처 드롭을 자동으로 반영
    # -------------------------------------------------------------
    # 만약 입력 데이터에 extension_category가 있다면 원-핫 인코딩 적용
    if 'extension_category' in df_input.columns:
        df_input = pd.get_dummies(df_input, columns=['extension_category'], drop_first=False)

    # 모델 객체에서 실제 학습할 때 쓰인 피처 이름 목록을 자동으로 추출
    if _model_instance is not None and hasattr(_model_instance, "feature_names_in_"):
        required_columns = list(_model_instance.feature_names_in_)
    else:
        # 모델을 못 불러왔을 경우 대비 fallback
        required_columns = [col for col in FEATURE_COLUMNS if col != 'suspicious_string_count']

    # 모델이 필요로 하는 컬럼 중 입력 데이터에 없는 건 0으로 채움
    for col in required_columns:
        if col not in df_input.columns:
            df_input[col] = 0

    # 모델이 학습했던 '정확한 순서와 피처'만 남기기
    df_input = df_input[required_columns]
    # -------------------------------------------------------------

    # 2. 모델이 정상적으로 로드된 경우 -> ML 모델 추론
    if _model_instance is not None:
        prob_percent = round(_model_instance.predict_proba(df_input)[0][1] * 100, 1)
        prediction = "Malicious" if prob_percent > 50.0 else "Benign"
    
    # 3. 모델 파일이 없을 경우 예외 방지용 Fallback (1단계 피처 명칭 기반 룰 스코어링)
    else:
        print("[ML Module Warning] 학습된 모델 파일(.pkl)이 없어 기본 규칙 기반 추론으로 대체합니다.")
        score = 5.0
        
        # 1단계 피처 항목 활용
        danger_cnt = ml_features.get("dangerous_function_count", 0)
        obfusc_cnt = ml_features.get("obfuscation_function_count", 0)
        ext_input_cnt = ml_features.get("external_input_count", 0)
        
        score += min((danger_cnt * 15) + (obfusc_cnt * 10) + (ext_input_cnt * 5), 50)
        
        if ml_features.get("executable_extension", 0) == 1:
            score += 20
        if ml_features.get("double_or_multi_extension", 0) == 1 or ml_features.get("extension_mismatch", 0) == 1:
            score += 25
            
        prob_percent = min(score, 99.0)
        prediction = "Malicious" if prob_percent > 50.0 else "Benign"

    # 상/중/하 위험도 등급 설정
    if prob_percent >= 80.0:
        risk_level = "HIGH (상)"
    elif prob_percent >= 40.0:
        risk_level = "MEDIUM (중)"
    else:
        risk_level = "LOW (하)"

    # 4. 결과 반환 (dict로 포맷)
    return {
        "prediction": prediction,
        "malware_probability": f"{prob_percent}%",
        "raw_probability": prob_percent,
        "risk_level": risk_level,
        "features_analyzed": ml_features
    }


def predict_malware_risk_json(ml_features: dict) -> str:
    """
    OpenAI Agent(Custom Tool) 전용 Wrapper 함수 (JSON 문자열 반환)
    """
    result = predict_malware_risk(ml_features)
    return json.dumps(result, ensure_ascii=False)

# ==========================================
# 모듈 작동 단독 테스트 (main 실행 시)
# ==========================================
if __name__ == "__main__":
    print("--- [ML 예측 모듈 작동 테스트] ---")

    # 1. 테스트용 임의 피처 데이터 생성
    dummy_features = {
        'file_size': 102400,
        'filename_length': 12,
        'extension_count': 1,
        'has_double_extension': 0,
        'has_uppercase_extension': 0,
        'has_unicode_control_char': 0,
        'special_char_ratio': 0.1,
        'is_executable_extension': 1,
        'is_script_extension': 0,
        'is_macro_document': 0,
        'is_archive_extension': 0,
        'is_unknown_extension': 0,
        'magic_bytes_known': 1,
        'magic_bytes_valid': 1,
        'extension_mime_mismatch': 0,
        'claimed_mime_mismatch': 0,
        'embedded_file_signature_count': 0,
        'byte_entropy': 6.5,
        'header_entropy': 5.8,
        'printable_ratio': 0.7,
        'null_byte_ratio': 0.1,
        'unique_byte_count': 200,
        'url_count': 3,
        'ip_address_count': 1,
        'base64_candidate_count': 0,
        'suspicious_command_count': 2,
        'execution_api_count': 5,
        'network_api_count': 2,
        'obfuscation_pattern_count': 1,
        'suspicious_string_count': 4,
        'archive_entry_count': 0,
        'executable_entry_count': 0,
        'script_entry_count': 0,
        'archive_depth': 0,
        'compression_ratio': 0.0,
        'archive_bomb_suspected': 0
    }

    # 2. 모델 로드 상태 확인
    if _model_instance is not None:
        print("✅ [.pkl 모델 성공적 로드] ML 모델 기반 추론을 시작합니다.")
    else:
        print("⚠️ [.pkl 모델 로드 실패] Fallback 규칙 기반 추론이 동작합니다.")

    # 3. 예측 함수 실행
    result = predict_malware_risk(dummy_features)

    # 4. 결과 출력
    print("\n--- [추론 결과 확인] ---")
    print(f"• 예측 결과 (prediction): {result['prediction']}")
    print(f"• 악성 확률 (malware_probability): {result['malware_probability']}")
    print(f"• 위험도 등급 (risk_level): {result['risk_level']}")