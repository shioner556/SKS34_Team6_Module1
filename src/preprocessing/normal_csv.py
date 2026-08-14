from pathlib import Path

import pandas as pd


REFERENCE_CSV = Path("data/preprocessed/dataset_bazaar.csv")
INPUT_CSV = Path("data/preprocessed/dataset_image_anomaly.csv")
OUTPUT_CSV = Path("data/preprocessed/dataset_image_anomaly_41cols.csv")


# 기존 데이터셋의 헤더만 읽음
reference_columns = pd.read_csv(
    REFERENCE_CSV,
    nrows=0,
    encoding="utf-8-sig",
).columns.tolist()

if len(reference_columns) != 41:
    raise ValueError(
        f"기준 CSV의 열이 41개가 아닙니다: {len(reference_columns)}개"
    )

df = pd.read_csv(INPUT_CSV, encoding="utf-8-sig")

missing_columns = [
    column for column in reference_columns
    if column not in df.columns
]

new_columns = [
    column for column in df.columns
    if column not in reference_columns
]

if missing_columns:
    raise ValueError(
        f"기존 41개 열 중 누락된 열이 있습니다: {missing_columns}"
    )

print(f"현재 열 개수: {len(df.columns)}")
print(f"제거할 신규 열: {new_columns}")

# 기준 CSV와 동일한 41개 열 및 순서만 유지
df = df.loc[:, reference_columns]

df.to_csv(
    OUTPUT_CSV,
    index=False,
    encoding="utf-8-sig",
)

print(f"최종 열 개수: {len(df.columns)}")
print(f"저장 경로: {OUTPUT_CSV}")