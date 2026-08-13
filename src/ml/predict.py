# 1단계 전처리(preprocess) 결과 피처를 입력받아 학습된 모델 파일(.pkl)을 이용해 악성 확률을 계산하는 코드

import os
import sys
import joblib
import pandas as pd
import json

# 1. 최상위 프로젝트 루트 경로
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 실제 모듈들이 들어있는 src 폴더 경로
SRC_DIR = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# models/random_forest.pkl 경로 조합
MODEL_PATH = os.path.join(BASE_DIR, "models", "random_forest.pkl")

# 1단계 정적 분석(preprocess) 결과의 수치형 피처 목록
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
    """
    1단계 피처 딕셔너리를 입력받아 ML 모델(또는 Fallback Rule)로 악성 확률 및 위험도를 예측
    """
    # 1. 입력 피처 데이터를 DataFrame 1줄 형태로 변환
    df_input = pd.DataFrame([ml_features])

    # 원-핫 인코딩 예외 처리
    if 'extension_category' in df_input.columns:
        df_input = pd.get_dummies(df_input, columns=['extension_category'], drop_first=False)

    # 모델 객체에서 실제 학습할 때 쓰인 피처 이름 목록 자동 추출
    if _model_instance is not None and hasattr(_model_instance, "feature_names_in_"):
        required_columns = list(_model_instance.feature_names_in_)
    else:
        # 모델을 못 불러왔을 경우 대비 fallback 피처 목록
        required_columns = [col for col in FEATURE_COLUMNS if col != 'suspicious_string_count']

    # 모델이 필요로 하는 컬럼 중 입력 데이터에 없는 항목은 0으로 채움
    for col in required_columns:
        if col not in df_input.columns:
            df_input[col] = 0

    # 모델 학습 피처 순서와 동일하게 정렬
    df_input = df_input[required_columns]

    # 2. 모델이 정상 로드된 경우 -> ML 모델 추론
    if _model_instance is not None:
        prob_percent = round(_model_instance.predict_proba(df_input)[0][1] * 100, 1)
        prediction = "Malicious" if prob_percent > 50.0 else "Benign"
    
    # 3. 모델 파일이 없을 경우 예외 방지용 Fallback (규칙 기반 스코어링)
    else:
        print("[ML Module Warning] 학습된 모델 파일(.pkl)이 없어 기본 규칙 기반 추론으로 대체합니다.")
        score = 5.0
        
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

    # 위험도 등급(Risk Level) 설정
    if prob_percent >= 80.0:
        risk_level = "HIGH (상)"
    elif prob_percent >= 40.0:
        risk_level = "MEDIUM (중)"
    else:
        risk_level = "LOW (하)"

    # 4. 결과 리턴 (dict 포맷)
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
# 모듈 작동 단독 테스트 (1단계 연동 실전 테스트)
# ==========================================
if __name__ == "__main__":
    print("--- [1단계 preprocessor.py 연동 테스트] ---")

    # 예비용 dummy_features
    dummy_features = {
        'file_size': 102400, 'filename_length': 12, 'extension_count': 1,
        'has_double_extension': 0, 'has_uppercase_extension': 0, 'has_unicode_control_char': 0,
        'special_char_ratio': 0.1, 'is_executable_extension': 1, 'is_script_extension': 0,
        'is_macro_document': 0, 'is_archive_extension': 0, 'is_unknown_extension': 0,
        'magic_bytes_known': 1, 'magic_bytes_valid': 1, 'extension_mime_mismatch': 0,
        'claimed_mime_mismatch': 0, 'embedded_file_signature_count': 0, 'byte_entropy': 6.5,
        'header_entropy': 5.8, 'printable_ratio': 0.7, 'null_byte_ratio': 0.1,
        'unique_byte_count': 200, 'url_count': 3, 'ip_address_count': 1,
        'base64_candidate_count': 0, 'suspicious_command_count': 2, 'execution_api_count': 5,
        'network_api_count': 2, 'obfuscation_pattern_count': 1, 'suspicious_string_count': 4,
        'archive_entry_count': 0, 'executable_entry_count': 0, 'script_entry_count': 0,
        'archive_depth': 0, 'compression_ratio': 0.0, 'archive_bomb_suspected': 0
    }

    # 1. 1단계 전처리 모듈 불러오기 테스트
    try:
        from preprocessing.preprocessor import preprocess
        
        sample_file = os.path.join(BASE_DIR, "README.md")
        
        if os.path.exists(sample_file):
            print(f"📄 '{sample_file}' 파일로 1단계 피처 추출 시도...")
            real_features = preprocess(sample_file)
            print("✅ 1단계 preprocessor.py 피처 추출 성공!")
        else:
            print("⚠️ sample_file이 없어 dummy_features로 대체합니다.")
            real_features = dummy_features

    except Exception as e:
        print(f"⚠️ 1단계 모듈 실행 실패 ({e}), dummy_features로 대체합니다.")
        real_features = dummy_features

    # 2. 2단계 ML 예측 함수 실행
    result = predict_malware_risk(real_features)

    # 3. 결과 출력
    print("\n--- [추론 결과 확인] ---")
    print(f"• 예측 결과 (prediction): {result['prediction']}")
    print(f"• 악성 확률 (malware_probability): {result['malware_probability']}")
    print(f"• 위험도 등급 (risk_level): {result['risk_level']}")