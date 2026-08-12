# 메인 함수
from pathlib import Path
from preprocessing.preprocessor import preprocess
from agent.agent import analyze_with_agent

def launch_preprocess(file):
    features = preprocess(file)
    print("[1단계] 파일 전처리 시작")
    print(features)
    return features

def launch_predict(features):
    """2단계: 머신러닝 예측"""
    print("[2단계] 머신러닝 예측 시작")
    pass

def launch_train(features):
    """2-A단계: 머신러닝 모델 학습"""
    print("[2-A단계] 머신러닝 모델 학습 시작")
    pass

def launch_analyze_with_agent(features, prediction):
    """3단계: OpenAI Agent 분석"""
    print("[3단계] Agent 분석 시작")
    # main 브랜치 머지 후 아래 주석 해제
    # from src.ml.predict import predict_malware_risk_json
    # prediction = json.loads(predict_malware_risk_json(features))
    result = analyze_with_agent(features, prediction)
    return result

def main():
    print("=== 악성 파일 분석 프로그램 ===")

    # 프로젝트 루트
    project_root = Path(__file__).resolve().parent.parent

    # 폴더 입력
    folder_name = input("분석할 폴더: ")

    # 프로젝트 루트 기준으로 폴더 찾기
    folder = project_root / folder_name

    # 폴더 존재 여부 확인
    if not folder.is_dir():
        print(f"폴더를 찾을 수 없습니다: {folder}")
        return

    # 폴더 안의 파일 목록 가져오기
    files = [file for file in folder.iterdir() if file.is_file()]

    # 파일이 없는 경우
    if not files:
        print("분석할 파일이 없습니다.")
        return

    # 일단 첫 번째 파일 선택
    file = files[0]

    print(f"분석 대상 파일: {file.name}")

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