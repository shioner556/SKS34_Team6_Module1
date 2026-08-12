import streamlit as st

st.title('FSD(File-Sniffing-Dog)')
st.write('---')
uploaded_file = st.file_uploader('🐶냄새를 맡을 수 있게 파일을 업로드 해주세요!')
st.write('---')
col1, mid, col2 = st.columns([10, 1, 10])

with col1:
    st.subheader('1단계 결과')

with mid:
    st.markdown(
        "<div style='border-left: 2px solid #888; height: 300px; margin: 0 auto;'></div>",
        unsafe_allow_html=True,
    )

with col2:
    st.subheader('2단계 결과')

st.write('---')

st.subheader('3단계 결과')