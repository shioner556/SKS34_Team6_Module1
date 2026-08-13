import os
import json
import joblib
import pandas as pd
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold

# dataset, 모델 저장 경로 설정
DATA_PATH = "data/preprocessed/dataset.csv" 
MODEL_SAVE_PATH = "models/random_forest.pkl"
METADATA_SAVE_PATH = "models/metadata.json"

# 데이터셋 로드 : csv 파일에 대해 데이터셋 로드
def load_dataset(file_path:str) -> pd.DataFrame:
    print('데이터셋 로드중...')
    # 파일이 존재하지 않는 경우 처리
    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"[오류] 학습용 데이터 파일이 존재하지 않습니다 : {file_path}"
        )

    df = pd.read_csv(file_path)

    if df.empty:
        raise ValueError("[오류] 파일이 비어있습니다.")

    print('====== 데이터셋 로드를 완료하였습니다. =====\n')
    return df

# 모델 학습   -> feature 내용 파악해서 수정할 것
def train_model(df:pd.DataFrame):
    # 전처리 및 feature engineering
    print('전처리 및 Feature Engineering 진행 중...')

    # 범주형 변수 처리 : extension_category(파일의 종류)
    df = pd.get_dummies(df, columns=['extension_category'], drop_first=False)

    # 정답 라벨을 매핑을 통해 처리(악성 : 1, 정상 : 0)
    label_mapping = {"malware": 1, "benign": 0}
    df['label'] = df['label'].map(label_mapping)

    # 학습에서 제외할 column 정의 : filename, file_path, label
    drop_cols = ['filename', 'filepath', 'label', 'suspicious_string_count']

    # Feature와 Target분리
    X = df.drop(columns=[col for col in drop_cols if col in df.columns], errors='ignore')
    y = df['label']

    # 학습할 데이터 확인
    print('===============================================================')
    print(f'총 샘플 수 : {len(df)} / 학습에 사용할 Feature 수 : {X.shape[1]}')
    print('===============================================================\n')

    # 데이터셋 train과 test로 분리
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 하이퍼파라미터 후보군 정의
    param_grid = {
        'n_estimators': [50, 100, 200],     # 트리의 개수
        'max_depth': [8, 10, 12, 15],       # 학습 깊이(과적합 방지)
        'criterion': ['gini', 'entropy']    # 데이터 분기 기
    }

    # 5-Fold Stratified Cross-Validation 설정
    cv_strategy = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # RandomForest 모델 생성 및 학습
    base_model = RandomForestClassifier(random_state=42)

    # GridSearchCV 객체 생성
    grid_search = GridSearchCV(
        estimator=base_model,       # 머신러닝 모델 지정
        param_grid=param_grid,      # 하이퍼파라미터 후보군 지정
        scoring='recall',           # 최적 파라미터를 선정할 때 기준이 되는 지표
        cv=cv_strategy,
    )

    print('====== 모델 학습 시작 =====')
    print("모델 학습 중...")

    grid_search.fit(X_train, y_train)
    model = grid_search.best_estimator_
    print(f'최적의 파라미터 : {grid_search.best_params_}')
    print('====== 모델 학습 완료 =====\n')

    # 예측 및 성능 평가
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print(f'===== 모델 성능 평가 =====')
    print(f'Accuracy : {accuracy_score(y_test, y_pred)}')
    print(classification_report(y_test, y_pred))

    # model 저장
    try:
        joblib.dump(model, MODEL_SAVE_PATH)
        print(f"===== 모델 저장 완료: {MODEL_SAVE_PATH} =====\n")
    except Exception as e:
        raise IOError(f"모델 저장 실패: {e}")

    # 모델 학습 메타데이터 저장
    print(f"===== 모델 학습 메타데이터 저장 =====")
    print("메타데이터 저장 중...")
    save_training_history(X_train, y_test, y_pred, grid_search, model)

# 모델 학습 메타데이터 저장
def save_training_history(X, y_test, y_pred, grid_search, model):
    now = datetime.now()
    version_str = now.strftime("%Y%m%d_%H%M%S")
    timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")

    report = classification_report(y_test, y_pred, output_dict=True)

    feature_importances = pd.Series(
        model.feature_importances_, index=X.columns
    ).sort_values(ascending=False).head(10).round(4).to_dict()

    metadata = {
        "version" : version_str,
        "trained_at" : timestamp_str,
        "data_info": {
            "total_samples" : len(X) + len(y_test),
            "train_samples" : len(X),
            "test_samples" : len(y_test),
            "feature_count" : X.shape[1]
        },
        "best_params" : grid_search.best_params_,
        "performance" : {
            "cv_best_recall" : round(grid_search.best_score_, 4),
            "test_accuracy" : round(accuracy_score(y_test, y_pred), 4),
            "test_malware_recall" : round(report['1']['recall'], 4),
            "test_malware_precision" : round(report['1']['precision'], 4),
            "test_malware_f1": round(report['1']['f1-score'], 4)
        },
        "top_10_features" : feature_importances
    }

    with open(METADATA_SAVE_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4, ensure_ascii=False)
    print(f"===== 모델 메타데이터 저장 완료: {METADATA_SAVE_PATH} =====\n")


# 메인 실행 파트
if __name__ == "__main__":
    print("===== trainer.py start ======\n")
    df = load_dataset(DATA_PATH)
    train_model(df)

