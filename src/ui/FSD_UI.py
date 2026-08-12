import tempfile
from pathlib import Path
import time
import random
import streamlit as st
# 1단계 코드 임포트
from preprocessor import preprocess

# 타이틀부분
st.title('FSD(File-Sniffing-Dog)')
st.write('---')
# 파일 업로드 부분
uploaded_file = st.file_uploader('🐶제가 냄새를 맡을 수 있게 파일을 업로드 해주세요!')
st.write('---')
col1, mid, col2 = st.columns([10, 1, 10])

with col1:
    st.subheader('1단계 결과')
    # 파일 탐지중 메세지 구분
    #---------------------------------------
    if uploaded_file is not None:
        placeholder = st.empty()
        dots = ["", ".", "..", "..."]
        end_time = time.time() + random.uniform(0,5)

        i = 0
        while time.time() < end_time :
            placeholder.markdown(f"🐶 가방 겉면 킁킁대는 중...{dots[i % 4]}")
            time.sleep(0.4)
            i += 1

        placeholder.empty()
        #----------------------------------------
        # 1단계 (preproccsor.py) 연결코드
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir) / uploaded_file.name
            tmp_path.write_bytes(uploaded_file.getvalue())
            result = preprocess(tmp_path)
        # (preproccsor.py) 결과 출력 
            st.json(result)

with mid:
    st.markdown(
        "<div style='border-left: 2px solid #888; height: 300px; margin: 0 auto;'></div>",
        unsafe_allow_html=True,
    )

with col2:
    st.subheader('2단계 결과')

st.write('---')

st.subheader('3단계 결과')