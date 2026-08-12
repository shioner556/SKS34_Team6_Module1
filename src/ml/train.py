import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

# dataset, 모델 저장 경로 설정
DATA_PATH = "data/processed/processed_data.csv"        # 파일명 정확히 수정
MODEL_SAVE_PATH = "models/random_forest.pkl"

# 데이터셋 로드 : csv 파일에 대해 데이터셋 로드
def load_dataset(file_path:str) -> pd.DataFrame:
    # 파일이 존재하지 않는 경우 처리
    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"학습용 데이터 파일이 존재하지 않습니다 : {file_path}"
        )

    return pd.read_csv(file_path)

# 모델 학습   -> feature 내용 파악해서 수정할 것
def train_model(df:pd.DataFrame):
    target_col = 'label'        # 정답 라벨 이후 전달 되면 수정

    # Feature와 Target분리
    X = df.drop(columns=[target_col])
    y = df[target_col]

    # 데이터셋 train과 test로 분리
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # RandomForest 모델 생성 및 학습
    model = RandomForestClassifier(
        n_estimators=100,  # 생성할 결정 트리 수
        max_depth=12,  # 트리의 최대 깊이 (과적합 방지)
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    # model 저장
    joblib.dump(model, MODEL_SAVE_PATH)
    print(f"모델 저장 완료: {MODEL_SAVE_PATH}")

if __name__ == "__main__":
    df = load_dataset(DATA_PATH)
    train_model(df)