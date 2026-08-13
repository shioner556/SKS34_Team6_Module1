import os
import pandas as pd
from sklearn.model_selection import train_test_split

# 1. 경로 설정
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PREPROCESSED_DIR = os.path.join(BASE_DIR, "data", "preprocessed")
ORIGINAL_CSV_PATH = os.path.join(PREPROCESSED_DIR, "dataset.csv")

def split_and_save_data():
    if not os.path.exists(ORIGINAL_CSV_PATH):
        print(f"원본 CSV 파일이 없습니다: {ORIGINAL_CSV_PATH}")
        return

    # 2. 원본 데이터셋 로드
    df = pd.read_csv(ORIGINAL_CSV_PATH)
    print(f"원본 데이터 총 개수: {len(df)}행")

    # 정답 라벨 컬럼명 자동 감지 ('label' 또는 'target' 등)
    label_col = None
    for col in ['label', 'target', 'is_malware', 'class']:
        if col in df.columns:
            label_col = col
            break

    # 3. Train (80%) : Test (20%) 분할
    # (stratify를 적용해 정상/악성 비율을 균등하게 분할)
    df_train, df_test = train_test_split(
        df, 
        test_size=0.2, 
        random_state=42, 
        stratify=df[label_col] if label_col else None
    )

    # 4. 분할된 CSV 파일 저장
    train_path = os.path.join(PREPROCESSED_DIR, "dataset_train.csv")
    test_path = os.path.join(PREPROCESSED_DIR, "dataset_test.csv")

    df_train.to_csv(train_path, index=False)
    df_test.to_csv(test_path, index=False)

    print("\n데이터 분할 완료!")
    print(f" ├── Train 데이터 (학습용 80%): {len(df_train)}개 -> dataset_train.csv")
    print(f" └── Test 데이터 (성능평가용 20%): {len(df_test)}개 -> dataset_test.csv")

if __name__ == "__main__":
    split_and_save_data()