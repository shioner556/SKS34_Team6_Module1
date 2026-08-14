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
# 3단계 코드 임포트
from agent.agent import analyze_with_agent


def _mock_report(file_name: str) -> dict:
    """테스트 모드용 가짜 3단계 리포트 (API 호출 없음)."""
    return {
        "risk_level": "중",
        "summary": f"[테스트 모드] '{file_name}' 가짜 리포트입니다. 실제 API를 호출하지 않았습니다.",
        "evidence": ["테스트용 근거 1", "테스트용 근거 2"],
        "related_cve": ["CVE-0000-0000"],
        "recommended_actions": ["테스트용 대응 방안 1", "테스트용 대응 방안 2"],
    }


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
# 마스코트 이미지 (flex로 간격을 직접 지정해서 나란히 붙임)
st.markdown(
    """
    <div style="display:flex; justify-content:center; align-items:center; gap:1px;">
        <img src="https://i.imgur.com/dI5iVsW.png" width="200">
        <img src="https://i.imgur.com/iEJON0C.png" width="320">
    </div>
    """,
    unsafe_allow_html=True,
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

# 3단계는 실제 OpenAI API를 호출해서 토큰이 소모되니, 화면/흐름만 확인할 땐 이 모드로
test_mode = st.checkbox('🧪 테스트 모드 (3단계 API 호출 없이 가짜 리포트로 확인)')

st.write('---')
col1, mid, col2 = st.columns([10, 1, 10])

# col1에서 계산한 걸 col2에서 재사용하기 위한 결과 저장소
results = []

with col1:
    st.subheader('파일을 받았어요!')
    # 파일 탐지중 메세지 구분
    #---------------------------------------
    if uploaded_files and sniff_clicked :
        dots = ["", ".", "..", "..."]
        total_files = len(uploaded_files)
        placeholder = st.empty()
        placeholder.markdown(f"🐶📁 파일 겉면 킁킁하는 중...\n\n(진행도 0/{total_files})")
        #----------------------------------------
        # 연결코드
        with tempfile.TemporaryDirectory() as tmp_dir:
            for idx, uploaded_file in enumerate(uploaded_files, start=1):
                tmp_path = Path(tmp_dir) / uploaded_file.name
                tmp_path.write_bytes(uploaded_file.getvalue())
                stage1_result = preprocess(tmp_path)
                stage2_result = predict_malware_risk(stage1_result)
                results.append((uploaded_file.name, stage1_result, stage2_result))
                # 1단계 탐지하면서 진행도로 표시
                placeholder.markdown(
                    f"🐶📁 파일 겉면 킁킁하는 중...{dots[idx % 4]}\n\n(진행도 {idx}/{total_files})"
                )

                # 상세보기 필요할 때(팀원이 보여달라고 할 때) 아래 주석 해제
                #with st.expander(f"📄 {uploaded_file.name} 상세보기"):
                  #st.json(stage1_result)
        placeholder.empty()
        if results:
            st.success("📁파일 확인 완료!")

with mid:
    st.markdown(
        "<div class = 'sniff-divider' style='border-left: 2px solid #888; height: 80px; margin: 0 auto;'></div>",
        unsafe_allow_html=True,
    )


with col2:
    st.subheader('파일을 열었어요!')
    if uploaded_files and sniff_clicked and results:
        # 2단계 파일 탐지하면서 진행도로 표시
        dots = ["", ".", "..", "..."]
        total_files = len(results)
        placeholder = st.empty()
        for idx, (file_name, _, stage2_result) in enumerate(results, start=1):
            placeholder.markdown(
                f"🐶📂 파일 안까지 킁킁하는 중...{dots[idx % 4]}\n\n(진행도 {idx}/{total_files})"
            )
            time.sleep(0.4)

            # 상세보기 필요할 때(팀원이 보여달라고 할 때) 아래 주석 해제
            #with st.expander(f"📄 {file_name} 상세보기"):
                  #summary = {
                     #"판정 결과": stage2_result["prediction"],
                     #"악성 확률": stage2_result["malware_probability"],
                     #"위험 레벨": stage2_result["risk_level"],
                  #}
                  #st.json(summary)
        placeholder.empty()
        st.success("📂파일 안쪽까지 확인완료!")

st.write('---')

st.subheader('전부 확인 완료!')
success_placeholder = st.empty()  # 완료 메시지가 나올 자리(서브헤더 바로 밑)를 미리 예약
if uploaded_files and sniff_clicked and results:
    total_files = len(results)
    placeholder = st.empty()
    for idx, (file_name, stage1_result, stage2_result) in enumerate(results, start=1):
        placeholder.markdown(f"🐶📄 최종 리포트 작성 중...\n\n(진행도 {idx}/{total_files})")
        if test_mode:
            report = _mock_report(file_name)
        else:
            report = analyze_with_agent(stage1_result, stage2_result)

        with st.expander(f"📂📄 {file_name} — 🚨위험도: {report['risk_level']} (🐾눌러 자세히보기)"):
            st.write(report["summary"])

            with st.expander("**📌판단 증거(🐾눌러서 자세히보기)**"):
             for evidence in report["evidence"]:
                st.write(f"- {evidence}")

            if report["related_cve"]:
                with st.expander("**📜관련 CVE(🐾눌러서 자세히보기)**"):
                    for cve in report["related_cve"]:
                        st.write(f"- {cve}")

            st.write("**🐶💡대응 방안 (이렇게 해봐요!!)**")
            for action in report["recommended_actions"]:
                st.write(f"- {action}")

    placeholder.empty()
    success_placeholder.success("📋보고서로 보여드릴게요!")    