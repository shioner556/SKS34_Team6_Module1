# 메인 함수
from pathlib import Path
from preprocessing.preprocessor import preprocess

def launch_preprocess(file):
    features = preprocess("sample.jpg.php")
    print("[1단계] 파일 전처리 시작")
    print(features)
    pass

def launch_predict(features):
    """2단계: 머신러닝 예측"""
    print("[2단계] 머신러닝 예측 시작")
    pass

def launch_analyze_with_agent(features, prediction):
    """3단계: OpenAI Agent 분석"""
    print("[3단계] Agent 분석 시작")
    pass

def main():
    print("=== 악성 파일 분석 프로그램 ===")

    # 프로젝트 루트
    project_root = Path(__file__).resolve().parent.parent

    # 파일 입력
    ## 테스트 샘플 경로 입력. test_samples
    file = input("분석할 파일 경로를 입력하세요: ")

    # 1단계
    features = launch_preprocess(file)

    # 2단계
    prediction = launch_predict(features)

    # 3단계
    result = launch_analyze_with_agent(features, prediction)

    # 결과 출력
    print("\n=== 분석 결과 ===")
    print(result)

if __name__ == "__main__":
    main()