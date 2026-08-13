import sys
from pathlib import Path
from streamlit.web import cli as stcli

def main():
    project_root = Path(__file__).resolve().parent
    
    # 실제 FSD_UI.py의 위치 경로 지정
    ui_script_path = project_root / "src" / "ui" / "FSD_UI.py"
    
    if not ui_script_path.exists():
        print(f"[ERROR] UI 파일을 찾을 수 없습니다: {ui_script_path}")
        return

    print("=== AI 파일 업로드 악성코드 탐지 시스템 (Streamlit UI) 구동 중... ===")
    
    # 터미널에서 'streamlit run src/ui/FSD_UI.py' 를 입력한 것과 동일하게 작동시킴
    sys.argv = ["streamlit", "run", str(ui_script_path)]
    sys.exit(stcli.main())

if __name__ == "__main__":
    main()