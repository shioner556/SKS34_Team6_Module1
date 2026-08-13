import tempfile
from pathlib import Path
import time
import random
import streamlit as st
# 1단계 코드 임포트
from preprocessor import preprocess
st.markdown(
    """
    <style>
    .stApp {
        background-image: linear-gradient(rgba(255, 255, 255, 0.75), rgba(255, 255, 255, 0.75)),
        url("https://i.imgur.com/u0Ei3uR.png");
        background-size: cover;
        background-position: center;
    }
    </style>
    """,
    unsafe_allow_html=True,
)
st.markdown(
    """
    <style>
    hr, div[data-testid="stMarkdownContainer"] hr {
    border-color: #444 !important;
    background-color: #444 !important;
}
    @media (max-width: 640px) {
        .sniff-divider { display: none; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)
# 타이틀부분
st.title('FSD(File-Sniffing-Dog)')
img_col1, img_col2, img_col3 = st.columns([1, 2, 1])
with img_col2:
    st.image(
        "https://i.imgur.com/iEJON0C.png",
        width=500,
    )
st.write('---')
st.write('🐶제가 냄새를 맡을 수 있게 파일을 업로드 해주세요!')
# 파일 업로드 부분
upload_col, button_col = st.columns([4,1], vertical_alignment= "center")
with upload_col:
 uploaded_files = st.file_uploader(
    '파일 업로드',
    accept_multiple_files = True,
    label_visibility='collapsed'
    ) 
with button_col:
 sniff_clicked = st.button('냄새 맡기')
st.write('---')
col1, mid, col2 = st.columns([10, 1, 10])

with col1:
    st.subheader('1단계 결과')
    # 파일 탐지중 메세지 구분
    #---------------------------------------
    if uploaded_files and sniff_clicked :
        placeholder = st.empty()
        dots = ["", ".", "..", "..."]
        end_time = time.time() + random.uniform(0,5)

        i = 0
        while time.time() < end_time :
            placeholder.markdown(f"🐶 가방 겉면 킁킁하는 중...{dots[i % 4]}")
            time.sleep(0.4)
            i += 1

        placeholder.empty()
        #----------------------------------------
        # 1단계 (preproccsor.py) 연결코드
        with tempfile.TemporaryDirectory() as tmp_dir:
            for uploaded_file in uploaded_files:
                tmp_path = Path(tmp_dir) / uploaded_file.name
                tmp_path.write_bytes(uploaded_file.getvalue())
                result = preprocess(tmp_path)
        # 출력코
                with st.expander(f"📄 {uploaded_file.name}"):
                    st.json(result)

with mid:
    st.markdown(
        "<div class = 'sniff-divider' style='border-left: 2px solid #888; height: 300px; margin: 0 auto;'></div>",
        unsafe_allow_html=True,
    )

with col2:
    st.subheader('2단계 결과')

st.write('---')

st.subheader('3단계 결과')