import os
import json
import glob
import joblib
import pandas as pd
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold

# dataset, 모델 저장 경로 설정
DATA_DIR_PATH = "data/preprocessed/"
MODEL_SAVE_PATH = "models/random_forest.pkl"
METADATA_SAVE_PATH = "models/metadata.json"

# 데이터셋 로드 : csv 파일에 대해 데이터셋 로드
def load_datasets(data_dir:str) -> pd.DataFrame:
    print('===== 데이터셋 로드 시작 =====')
    print('데이터셋 로드중...')

    # dataset_test.csv는 로드 대상에서 제외
    csv_files = [
        f for f in glob.glob(os.path.join(data_dir, '*.csv')) 
        if not os.path.basename(f).startswith('dataset_test')
    ]

    # 경로 안 모든 csv 파일 경로 수집 -> 실제 테스트에서 사용
    csv_files = glob.glob(os.path.join(data_dir, '*.csv'))

    if not csv_files:
        raise FileNotFoundError(
            f"[오류] 해당 경로에 csv 파일이 존재하지 않습니다 : {data_dir}"
        )

    df_list = []
    for file_path in csv_files:
        try:
            df = pd.read_csv(file_path)
            if not df.empty:
                df_list.append(df)
                print(f'- 파일 로드 완료 : {os.path.basename(file_path)} ({len(df)}개 샘플)')
        except Exception as e:
            print(f'[오류] {os.path.basename(file_path)} 파일 읽기 실패: {e}')

    if not df_list:
        raise ValueError('[오류] 유효한 데이터 파일이 담긴 csv 파일이 없습니다.')

    # 여러 데이터 프레임을 하나로 결합
    combined_df = pd.concat(df_list, ignore_index=True)

    combined_df = combined_df.drop_duplicates()

    print(f"===== 총 {len(df_list)}개 csv 파일 통합 완료 (총 샘플 수 : {len(combined_df)}) ======\n")
    return combined_df

# 다운 샘플링 : 확장자별 데이터 불균형을 해소하기 위해 사용(.pdf)
def downsample_by_extension(df: pd.DataFrame, ext_col: str = 'extension_category', max_samples: int = 2000) -> pd.DataFrame:
    print('===== 다운 샘플링 시작(최대 샘플 수 2000개로 설정) =====')
    if ext_col not in df.columns:
        print(f'[경고] {ext_col} 컬럼을 찾을 수 없어 다운샘플링을 진행하지 않습니다.')
        return df

    sampled_df = []
    for ext, group in df.groupby(ext_col):
        # max_samples 수를 넘어가는 확장자는 지정한 max_samples 수만큼 무작위 추출
        if len(group) > max_samples:
            sampled_group = group.sample(n=max_samples, random_state=42)
            sampled_df.append(sampled_group)
        else: 
            sampled_df.append(group)

    result_df = pd.concat(sampled_df, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

    print('===============================================================')
    print(f'기존 샘플 수 : {len(df)}개 / 조정된 샘플 수 : {len(result_df)}개(확장자당 최대 {max_samples}개)')
    print('===============================================================')
    return result_df


# 모델 학습   -> feature 내용 파악해서 수정할 것
def train_model(df:pd.DataFrame):
    # 전처리 및 feature engineering
    print('전처리 및 Feature Engineering 진행 중...')

    # 정답 라벨을 매핑을 통해 처리(악성 : 1, 정상 : 0)
    label_mapping = {
        "malware": 1, "1": 1, 1: 1,
        "benign": 0, "0": 0, 0: 0
    }
    df['label'] = df['label'].map(label_mapping)

    # 다운 샘플링 : extension_category별로 2000개의 샘플 수 제한
    df = downsample_by_extension(df, ext_col='extension_category', max_samples=2000)

    # 범주형 변수 처리 : extension_category(파일의 종류)
    df = pd.get_dummies(df, columns=['extension_category'], drop_first=False)

    # 학습에서 제외할 column 정의 : filename, file_path, label
    drop_cols = ['filename', 'filepath', 'label', 'suspicious_string_count']

    # Feature와 Target분리
    X = df.drop(columns=[col for col in drop_cols if col in df.columns], errors='ignore')
    y = df['label']

    # 라벨 분포 및 비율 확인
    label_counts = y.value_counts()
    label_ratios = y.value_counts(normalize=True) * 100
    
    malware_cnt = label_counts.get(1, 0)
    benign_cnt = label_counts.get(0, 0)
    malware_pct = label_ratios.get(1, 0.0)
    benign_pct = label_ratios.get(0, 0.0)

    # 학습할 데이터 확인
    print('===============================================================')
    print(f'총 샘플 수 : {len(df)} / 학습에 사용할 Feature 수 : {X.shape[1]}')
    print(f'• 악성(Malware, 1) : {malware_cnt}개 ({malware_pct:.1f}%)')
    print(f'• 정상(Benign, 0)  : {benign_cnt}개 ({benign_pct:.1f}%)')
    print('===============================================================\n')

    # 데이터셋 train과 test로 분리
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 하이퍼파라미터 후보군 정의
    param_grid = {
        'n_estimators': [50, 100, 200],                 # 트리의 개수
        'max_depth': [8, 10, 12, 15, 20, 25, 30],       # 학습 깊이(과적합 방지)
        'criterion': ['gini', 'entropy']                # 데이터 분기 기준
    }

    # 5-Fold Stratified Cross-Validation 설정
    cv_strategy = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # RandomForest 모델 생성 및 학습
    base_model = RandomForestClassifier(class_weight='balanced', random_state=42)

    # GridSearchCV 객체 생성 (하이퍼파라미터 자동 탐색을 위한 객체)
    grid_search = GridSearchCV(
        estimator=base_model,       # 머신러닝 모델 지정
        param_grid=param_grid,      # 하이퍼파라미터 후보군 지정
        scoring='recall',           # 최적 파라미터를 선정할 때 기준이 되는 지표
        cv=cv_strategy,
        n_jobs=-1
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

    #학습 일시 생성
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    report = classification_report(y_test, y_pred, output_dict=True)

    # 트리 분할 시 중요하게 활용한 수치 추출
    feature_importances = pd.Series(
        model.feature_importances_, index=X.columns
    ).sort_values(ascending=False).head(10).round(4).to_dict()

    metadata = {
        "trained_at" : timestamp,
        "data_info": {
            "total_samples" : len(X) + len(y_test),
            "train_samples" : len(X),
            "test_samples" : len(y_test),
            "feature_count" : X.shape[1]
        },
        "best_params" : grid_search.best_params_,
        "performance" : {
            "cv_best_recall" : round(grid_search.best_score_, 4),           #5-Fold CV 평균 Recall 최고점
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
    df = load_datasets(DATA_DIR_PATH)
    train_model(df)