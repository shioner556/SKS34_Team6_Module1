# 1단계 전처리(preprocess) 결과 피처를 입력받아 학습된 모델 파일(.pkl)을 이용해 악성 확률을 계산하는 코드

import os
import sys
import glob
import joblib
import pandas as pd
import json
from sklearn.metrics import accuracy_score, classification_report

# 1. 최상위 프로젝트 루트 경로
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 실제 모듈들이 들어있는 src 폴더 경로
SRC_DIR = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# 모델 저장 경로 (malware_rf_model.pkl 및 random_forest.pkl 호환)
MODEL_PATH = os.path.join(BASE_DIR, "models", "malware_rf_model.pkl")
if not os.path.exists(MODEL_PATH):
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
            print(f"📦 모델 파일 로드 성공: {MODEL_PATH}")
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
    df_input = pd.DataFrame([ml_features])

    if 'extension_category' in df_input.columns:
        df_input = pd.get_dummies(df_input, columns=['extension_category'], drop_first=False)

    if _model_instance is not None and hasattr(_model_instance, "feature_names_in_"):
        required_columns = list(_model_instance.feature_names_in_)
    else:
        required_columns = [col for col in FEATURE_COLUMNS if col != 'suspicious_string_count']

    for col in required_columns:
        if col not in df_input.columns:
            df_input[col] = 0

    df_input = df_input[required_columns].fillna(0)

    if _model_instance is not None:
        prob_percent = round(_model_instance.predict_proba(df_input)[0][1] * 100, 1)
        prediction = "Malicious" if prob_percent > 50.0 else "Benign"
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

    if prob_percent >= 80.0:
        risk_level = "HIGH (상)"
    elif prob_percent >= 40.0:
        risk_level = "MEDIUM (중)"
    else:
        risk_level = "LOW (하)"

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
# 폴더 내 모든 파일 배치(Batch) 추론 및 성능 검증
# ==========================================
if __name__ == "__main__":
    preprocessed_dir = os.path.join(BASE_DIR, "data", "preprocessed")
    csv_files = glob.glob(os.path.join(preprocessed_dir, "dataset_*.csv"))

    print(f"=== 전체 {len(csv_files)}개 preprocessed CSV 병합 배치 추론 및 성능 검증 시작 ===\n", flush=True)

    if not csv_files:
        print(f"❌ preprocessed 폴더에 CSV 파일이 존재하지 않습니다: {preprocessed_dir}", flush=True)
        sys.exit(1)

    try:
        # 모든 dataset_*.csv 파일 불러와 하나로 병합
        df_list = [pd.read_csv(f) for f in csv_files]
        df_dataset = pd.concat(df_list, ignore_index=True)
        print(f"📊 총 {len(df_dataset)}개 병합 데이터 행(Row) 로드 완료!\n", flush=True)

        # 정답 라벨 컬럼 자동 감지 ('label', 'target', 'is_malware', 'class')
        label_col = None
        for col in ['label', 'target', 'is_malware', 'class']:
            if col in df_dataset.columns:
                label_col = col
                break

        y_true = []
        y_pred = []

        for idx, row in df_dataset.iterrows():
            feature_dict = row.to_dict()
            res = predict_malware_risk(feature_dict)

            file_identifier = feature_dict.get('filename', f"Row #{idx+1}")
            pred_label = res['prediction']

            if label_col is not None:
                raw_label = row[label_col]
                actual_label = "Malicious" if str(raw_label).lower() in ["1", "true", "malicious", "malware"] else "Benign"
                
                y_true.append(actual_label)
                y_pred.append(pred_label)

                is_correct = (pred_label == actual_label)
                status = "✅" if is_correct else "❌"
                
                # 📌 개별 데이터 추론 결과 실시간 출력
                print(f"{status} [{file_identifier}] -> 예측: {pred_label} (실제: {actual_label}) | 확률: {res['malware_probability']} | 위험도: {res['risk_level']}", flush=True)
            else:
                print(f" [{file_identifier}] -> 예측: {pred_label} | 확률: {res['malware_probability']} | 위험도: {res['risk_level']}", flush=True)

        # 성능 검증 평가 결과 출력
        if y_true and y_pred:
            acc = accuracy_score(y_true, y_pred) * 100
            print("\n" + "="*50)
            print("[최종 평가 결과 (Model Evaluation Report)]")
            print("="*50)
            print(f"전체 Accuracy (정확도): {acc:.2f}%")
            print("\n세부 리포트 (Classification Report):")
            print(classification_report(y_true, y_pred, target_names=["Benign", "Malicious"]))
            print("="*50)

    except Exception as e:
        print(f"❌ CSV 추론 및 평가 중 오류 발생: {e}", flush=True)