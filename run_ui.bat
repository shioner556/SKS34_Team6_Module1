@echo off
:: 1. 배치 파일이 있는 프로젝트 최상위 폴더로 이동
cd /d "%~dp0"

:: 2. 가상환경 활성화 (프로젝트 루트의 .venv 활성화)
call .venv\Scripts\activate.bat

:: 3. Streamlit 실행 (src/ui/FSD_UI.py 직접 실행)
streamlit run src\ui\FSD_UI.py

pause