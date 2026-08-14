import sys
from pathlib import Path
from streamlit.web import cli as stcli

def main():
    # main.py가 src/ 안에 있으므로 current_dir은 'src' 폴더입니다.
    current_dir = Path(__file__).resolve().parent
    
    # 'src' 폴더 바로 아래의 'ui/FSD_UI.py'를 지정합니다.
    ui_script_path = current_dir / "ui" / "FSD_UI.py"
    
    if not ui_script_path.exists():
        print(f"[ERROR] UI 파일을 찾을 수 없습니다: {ui_script_path}")
        return

    print("=== AI 파일 업로드 악성코드 탐지 시스템 (Streamlit UI) 구동 중... ===")
    
    sys.argv = ["streamlit", "run", str(ui_script_path)]
    sys.exit(stcli.main())

if __name__ == "__main__":
    main()