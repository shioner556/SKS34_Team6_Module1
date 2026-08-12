import tempfile
from pathlib import Path
import time
import random
import streamlit as st
from preprocessor import preprocess
from predict import predict_malware_risk


def sniff_animation(message: str):
    placeholder = st.empty()
    dots = ["", ".", "..", "..."]
    end_time = time.time() + random.uniform(0, 5)

    i = 0
    while time.time() < end_time:
        placeholder.markdown(f"{message}{dots[i % 4]}")
        time.sleep(0.4)
        i += 1
    placeholder.empty()


st.title('FSD(File-Sniffing-Dog)')
st.write('---')
st.write('🐶제가 냄새를 맡을 수 있게 파일을 업로드 해주세요!')

upload_col, button_col = st.columns([4, 1], vertical_alignment="center")
with upload_col:
    uploaded_files = st.file_uploader(
        '파일 업로드',
        accept_multiple_files=True,
        label_visibility='collapsed',
    )
with button_col:
    sniff_clicked = st.button('냄새 맡기')
st.write('---')

stage1_results = []  # (파일명, 1단계 결과)

if uploaded_files and sniff_clicked:
    sniff_animation("🐶 가방 겉면 킁킁하는 중...")

    with tempfile.TemporaryDirectory() as tmp_dir:
        for uploaded_file in uploaded_files:
            tmp_path = Path(tmp_dir) / uploaded_file.name
            tmp_path.write_bytes(uploaded_file.getvalue())
            stage1_results.append((uploaded_file.name, preprocess(tmp_path)))

col1, mid, col2 = st.columns([10, 1, 10])

with col1:
    st.subheader('1단계 결과')
    for filename, stage1_result in stage1_results:
        with st.expander(f"📄 {filename}"):
            st.json(stage1_result)

with mid:
    st.markdown(
        "<div style='border-left: 2px solid #888; height: 300px; margin: 0 auto;'></div>",
        unsafe_allow_html=True,
    )

with col2:
    st.subheader('2단계 결과')
    if stage1_results:
        sniff_animation("🐶 가방 속까지 파고드는 중...")
        for filename, stage1_result in stage1_results:
            stage2_result = predict_malware_risk(stage1_result)
            with st.expander(f"📄 {filename}"):
                st.json(stage2_result)

st.write('---')

st.subheader('3단계 결과')