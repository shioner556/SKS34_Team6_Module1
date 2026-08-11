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