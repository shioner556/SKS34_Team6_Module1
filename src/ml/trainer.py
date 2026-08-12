import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

# dataset, 모델 저장 경로 설정
DATA_PATH = "data/preprocessed/dataset.csv" 
MODEL_SAVE_PATH = "models/random_forest.pkl"

# 데이터셋 로드 : csv 파일에 대해 데이터셋 로드
def load_dataset(file_path:str) -> pd.DataFrame:
    print('데이터셋 로드중...')
    # 파일이 존재하지 않는 경우 처리
    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"학습용 데이터 파일이 존재하지 않습니다 : {file_path}"
        )

    print('====== 데이터셋 로드를 완료하였습니다. =====\n')
    return pd.read_csv(file_path)

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
    X = df.drop(columns=[col for col in drop_cols if col in df.columns])
    y = df['label']

    # 학습할 데이터 확인
    print('===============================================================')
    print(f'총 샘플 수 : {len(df)} / 학습에 사용할 Feature 수 : {X.shape[1]}')
    print('===============================================================')

    # 데이터셋 train과 test로 분리
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # RandomForest 모델 생성 및 학습
    print('====== 모델 학습 시작 =====')
    print("모델 학습 중...")
    model = RandomForestClassifier(
        n_estimators=100,  # 생성할 결정 트리 수
        max_depth=12,  # 트리의 최대 깊이 (과적합 방지)
        random_state=42
    )
    model.fit(X_train, y_train)

    # 예측 및 성능 평가
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print(f'===== 모델 성능 평가 =====')
    print(f'Accuracy : {accuracy_score(y_test, y_pred)}')
    print(classification_report(y_test, y_pred))

    # model 저장
    joblib.dump(model, MODEL_SAVE_PATH)
    print(f"모델 저장 완료: {MODEL_SAVE_PATH}")

if __name__ == "__main__":
    print("===== trainer.py start ======")
    df = load_dataset(DATA_PATH)
    train_model(df)