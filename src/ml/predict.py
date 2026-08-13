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

    # 결측치(NaN) 0으로 채우기 및 모델 학습 피처 순서와 동일하게 정렬
    df_input = df_input[required_columns].fillna(0)

    # 2. 모델이 정상 로드된 경우 -> ML 모델 추론
    if _model_instance is not None:
        prob_percent = round(_model_instance.predict_proba(df_input)[0][1] * 100, 1)
        prediction = "Malicious" if prob_percent > 50.0 else "Benign"
    
    # 3. 모델 파일이 없을 경우 예외 방지용 Fallback (규칙 기반 스코어링)
    else:
        print("[ML Module Warning] 학습된 모델 파일(.pkl)이 없어 기본 규칙 기반 추론으로 대체합니다.")
        score = 5.0
        
        suspicious_cmd = ml_features.get("suspicious_command_count", 0)
        obfusc_pat = ml_features.get("obfuscation_pattern_count", 0)
        exec_api = ml_features.get("execution_api_count", 0)
        
        score += min((suspicious_cmd * 15) + (obfusc_pat * 10) + (exec_api * 5), 50)
        
        if ml_features.get("is_executable_extension", 0) == 1:
            score += 20
        if ml_features.get("has_double_extension", 0) == 1 or ml_features.get("extension_mime_mismatch", 0) == 1:
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
# 폴더 내 모든 파일 배치(Batch) 추론 테스트
# ==========================================
if __name__ == "__main__":
    csv_filename = "dataset.csv"  # 테스트 및 실전 배치 추론용 CSV 파일명 (필요 시 dataset_test.csv 등으로 변경)
    csv_path = os.path.join(BASE_DIR, "data", "preprocessed", csv_filename)

    print(f"=== 🚀 {csv_filename} 기반 배치 추론 시작 ===", flush=True)

    if not os.path.exists(csv_path):
        print(f"❌ CSV 파일이 존재하지 않습니다: {csv_path}", flush=True)
        sys.exit(1)

    try:
        # 1. 전처리 완료된 CSV 데이터 읽기
        df_dataset = pd.read_csv(csv_path)
        print(f"📊 총 {len(df_dataset)}개 데이터 행(Row) 로드 완료!\n", flush=True)

        # 2. 행 단위로 딕셔너리 변환 후 ML 모델 추론 진행
        success_cnt = 0
        for idx, row in df_dataset.iterrows():
            feature_dict = row.to_dict()
            
            # 2단계 ML 모델 추론
            res = predict_malware_risk(feature_dict)

            # 파일명 또는 인덱스 가져오기
            file_identifier = feature_dict.get('filename', f"Row #{idx+1}")

            print(f"📄 [{file_identifier}] -> 예측: {res['prediction']} | 확률: {res['malware_probability']} | 위험도: {res['risk_level']}", flush=True)
            success_cnt += 1

        print(f"\n✅ 총 {success_cnt}개 데이터 추론 완료!", flush=True)

    except Exception as e:
        print(f"❌ CSV 추론 중 오류 발생: {e}", flush=True)