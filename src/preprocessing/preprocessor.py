# 1단계 정적 처리, 전처리 과정입니다.
import math
import re
from collections import Counter
from pathlib import Path

try:
    ## 콘솔창에 pip install python-magic
    import magic
except ImportError:
    magic = None


# =========================================================
# 설정
# =========================================================

# 서버에서 실행될 가능성이 있는 확장자
EXECUTABLE_EXTENSIONS = {
    ".php",
    ".php3",
    ".php4",
    ".php5",
    ".phtml",
    ".jsp",
    ".jspx",
    ".asp",
    ".aspx",
    ".cgi",
}

# 정적 분석에서 확인할 위험 함수
DANGEROUS_FUNCTION_PATTERNS = [
    r"\bsystem\s*\(",
    r"\bexec\s*\(",
    r"\beval\s*\(",
    r"\bpassthru\s*\(",
    r"\bshell_exec\s*\(",
    r"\bpopen\s*\(",
    r"\bRuntime\s*\.\s*exec\s*\(",
]

# 난독화가 의심되는 함수
OBFUSCATION_PATTERNS = [
    r"\bbase64_decode\s*\(",
    r"\bbase64_encode\s*\(",
]

# 외부 입력 참조를 단순 탐지하기 위한 패턴
EXTERNAL_INPUT_PATTERNS = [
    r"\$_GET\b",
    r"\$_POST\b",
    r"\$_REQUEST\b",
    r"\$_COOKIE\b",
    r"\$_FILES\b",
]


# =========================================================
# 1. 파일명 분석
# =========================================================

def analyze_filename(filename):
    """
    파일명에서 확장자 관련 Feature를 추출한다.
    """

    path = Path(filename)
    name = path.name

    # 마지막 확장자
    suffix = path.suffix.lower()

    # 전체 확장자 목록
    parts = name.split(".")

    # 파일명 자체는 제외
    extensions = []

    if len(parts) > 1:
        for part in parts[1:]:
            if part:
                extensions.append("." + part.lower())

    extension_count = len(extensions)

    # 위험 확장자 포함 여부
    executable_extension = any(
        ext in EXECUTABLE_EXTENSIONS
        for ext in extensions
    )

    return {
        "extension_count": extension_count,
        "last_extension": suffix,
        "executable_extension": int(executable_extension),
        "double_or_multi_extension": int(extension_count >= 2),
    }


# =========================================================
# 2. MIME / Magic Bytes 분석
# =========================================================

def detect_mime_type(file_path):
    """
    python-magic을 이용하여 실제 MIME 타입을 확인한다.
    """

    if magic is None:
        return None

    try:
        return magic.from_file(str(file_path), mime=True)
    except Exception:
        return None


def analyze_file_type(file_path, filename):
    """
    표시된 확장자와 실제 파일 형식의 관계를 분석한다.
    """

    filename_info = analyze_filename(filename)

    displayed_extension = filename_info["last_extension"]
    mime_type = detect_mime_type(file_path)

    # 현재는 단순한 임시 비교.
    # 실제 구현에서는 MIME <-> 확장자 매핑 테이블을 만드는 것이 좋다.
    extension_mismatch = 0

    if mime_type is not None:
        if displayed_extension == ".jpg" and not mime_type.startswith("image/jpeg"):
            extension_mismatch = 1

        elif displayed_extension == ".png" and not mime_type.startswith("image/png"):
            extension_mismatch = 1

        elif displayed_extension == ".gif" and not mime_type.startswith("image/gif"):
            extension_mismatch = 1

        elif displayed_extension == ".pdf" and mime_type != "application/pdf":
            extension_mismatch = 1

    return {
        "displayed_extension": displayed_extension,
        "mime_type": mime_type,
        "extension_mismatch": extension_mismatch,
    }


# =========================================================
# 3. 파일 내용 분석
# =========================================================

def read_file_content(file_path):
    """
    파일을 텍스트로 읽을 수 있는 경우 내용을 반환한다.

    주의:
    파일을 실행하지 않고 단순히 읽기만 한다.
    """

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    except Exception:
        return ""


def count_regex_patterns(content, patterns):
    """
    여러 정규표현식 패턴의 전체 탐지 횟수를 반환한다.
    """

    count = 0

    for pattern in patterns:
        count += len(re.findall(pattern, content, re.IGNORECASE))

    return count


def calculate_entropy(file_path):
    """
    파일 바이트의 Shannon entropy를 계산한다.
    """

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)

        entropy = 0.0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    except Exception:
        return 0.0


def analyze_content(file_path):
    """
    파일 내용에서 Feature를 추출한다.
    """

    content = read_file_content(file_path)

    dangerous_count = count_regex_patterns(
        content,
        DANGEROUS_FUNCTION_PATTERNS
    )

    obfuscation_count = count_regex_patterns(
        content,
        OBFUSCATION_PATTERNS
    )

    external_input_count = count_regex_patterns(
        content,
        EXTERNAL_INPUT_PATTERNS
    )

    try:
        file_size = Path(file_path).stat().st_size
    except Exception:
        file_size = 0

    entropy = calculate_entropy(file_path)

    return {
        "dangerous_function_count": dangerous_count,
        "obfuscation_function_count": obfuscation_count,
        "external_input_count": external_input_count,
        "file_entropy": entropy,
        "file_size": file_size,
    }


# =========================================================
# 전체 전처리
# =========================================================

def preprocess(file_path):
    """
    파일 하나를 입력받아 ML에서 사용할 Feature를 반환한다.

    전체 흐름:
        파일
        ↓
        파일명 분석
        ↓
        파일 형식 분석
        ↓
        파일 내용 분석
        ↓
        Feature Dictionary
    """

    filename = Path(file_path).name

    filename_features = analyze_filename(
        filename
    )

    file_type_features = analyze_file_type(
        file_path,
        filename
    )

    content_features = analyze_content(
        file_path
    )

    features = {}

    features.update(filename_features)
    features.update(file_type_features)
    features.update(content_features)

    return features