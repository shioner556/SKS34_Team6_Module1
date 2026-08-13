import tempfile
import sys
from pathlib import Path
import time
import random
import streamlit as st
# src/ 를 sys.path에 추가
sys.path.append(str(Path(__file__).resolve().parent.parent))  

# 1단계 코드 임포트
from preprocessing.preprocessor import preprocess
# 2단계 코드 임포트
from ml.predict import predict_malware_risk
# 배경화면
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
# 선 어둡게
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
    .block-container {
        background-color: rgba(255, 255, 255, 0.55);
        border-radius: 16px;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.15);
        padding: 2rem 3rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)
# 타이틀부분
st.title('FSD(File-Sniffing-Dog)')
# 마스코트 이미지
img_col1, img_col2, img_col3 = st.columns([1, 2, 1])
with img_col2:
    st.image(
        "https://i.imgur.com/iEJON0C.png",
        width=500,
    )
st.write('---')
st.write('🐶제가 냄새를 맡을 수 있게 파일을 업로드 해주세요!')
# 파일 업로드 부분
if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = 0

def _reset_uploader():
    st.session_state.uploader_key += 1

upload_col, button_col, reset_col = st.columns([4,1,1], vertical_alignment= "center")
with upload_col:
 uploaded_files = st.file_uploader(
    '파일 업로드',
    accept_multiple_files = True,
    label_visibility='collapsed',
    key=f"file_uploader_{st.session_state.uploader_key}",
    )
 # 탐지 시작 버튼
with button_col:
 sniff_clicked = st.button('냄새 맡기')
 # 파일 업로드 초기화 버튼
with reset_col:
 st.button('다시 하기', on_click=_reset_uploader)
st.write('---')
col1, mid, col2 = st.columns([10, 1, 10])

# col1에서 계산한 걸 col2에서 재사용하기 위한 결과 저장소
results = []

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
            placeholder.markdown(f"🐶📁 가방 겉면 킁킁하는 중...{dots[i % 4]}")
            time.sleep(0.4)
            i += 1

        placeholder.empty()
        #----------------------------------------
        # 연결코드
        with tempfile.TemporaryDirectory() as tmp_dir:
            with st.container(height=400):
                for uploaded_file in uploaded_files:
                    tmp_path = Path(tmp_dir) / uploaded_file.name
                    tmp_path.write_bytes(uploaded_file.getvalue())
                    stage1_result = preprocess(tmp_path)
                    stage2_result = predict_malware_risk(stage1_result)
                    results.append((uploaded_file.name, stage1_result, stage2_result))
                    # 상세 결과는 3단계 레포트에서 합쳐서 보여줌
                    st.write(f"📁 {uploaded_file.name}")

                    # 상세보기 필요할 때(팀원이 보여달라고 할 때) 아래 주석 해제
                    #with st.expander(f"📄 {uploaded_file.name} 상세보기"):
                      #st.json(stage1_result)
        if results:
            st.success("가방 확인 완료!")

with mid:
    st.markdown(
        "<div class = 'sniff-divider' style='border-left: 2px solid #888; height: 300px; margin: 0 auto;'></div>",
        unsafe_allow_html=True,
    )
    

with col2:
    st.subheader('2단계 결과')
    if uploaded_files and sniff_clicked :
        placeholder = st.empty()
        dots = ["", ".", "..", "..."]
        end_time = time.time() + random.uniform(0,5)

        i = 0
        while time.time() < end_time :
            placeholder.markdown(f"🐶📂 가방 안까지 킁킁하는 중...{dots[i % 4]}")
            time.sleep(0.4)
            i += 1
        placeholder.empty()
    if results:
        with st.container(height=400):
            for file_name, _, stage2_result in results:
                st.write(f"📂 {file_name}")
                # 상세 결과는 3단계 레포트에서 합쳐서 보여줌

                # 상세보기 필요할 때(팀원이 보여달라고 할 때) 아래 주석 해제
                #with st.expander(f"📄 {file_name} 상세보기"):
                      #summary = {
                         #"판정 결과": stage2_result["prediction"],
                         #"악성 확률": stage2_result["malware_probability"],
                         #"위험 레벨": stage2_result["risk_level"],
                      #}
                      #st.json(summary)
        st.success("가방 안쪽까지 확인완료!")

st.write('---')
 
st.subheader('3단계 결과') 