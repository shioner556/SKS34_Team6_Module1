# Streamlit을 사용하기에 실제 사용자가 실행하는 곳은 app.py가 될 가능성이 높습니다.
# 4단계 UI 과정입니다.

import streamlit as st
from pipeline import run_pipeline

def main():
    st.title("AI 악성 파일 분석기")

    uploaded_file = st.file_uploader(
        "분석할 파일을 업로드하세요."
    )

    if uploaded_file is not None:

        if st.button("분석 시작"):

            result = run_pipeline(uploaded_file)

            st.write(result)


if __name__ == "__main__":
    main()