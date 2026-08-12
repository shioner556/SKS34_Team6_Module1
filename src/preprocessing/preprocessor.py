"""
Static File Feature Extractor
=============================

Output Feature 명세(37개)를 기준으로 파일 하나에서 정적 Feature를 추출한다.

원칙:
- 파일을 실행하지 않는다.
- 파일명 / 확장자 / Magic Bytes / MIME / 바이트 통계 /
  문자열 패턴 / 압축 파일 메타데이터만 정적으로 분석한다.
- claimed_mime은 업로드 당시 Content-Type을 알고 있을 때만 전달한다.
- 압축 분석은 기본적으로 ZIP을 표준 라이브러리로 지원하고,
  RAR/7z는 선택적 패키지가 설치되어 있으면 추가 분석한다.

선택적 패키지:
    pip install python-magic
    pip install rarfile py7zr

Windows에서 python-magic이 잘 동작하지 않는 경우에는
Magic Bytes 기반 fallback이 사용된다.
"""

from __future__ import annotations

import base64
import math
import mimetypes
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------

try:
    import magic  # type: ignore
except ImportError:
    magic = None

try:
    import rarfile  # type: ignore
except ImportError:
    rarfile = None

try:
    import py7zr  # type: ignore
except ImportError:
    py7zr = None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# "알려진 확장자" 집합.
# extension_count는 이 목록에 있는 확장자만 센다.
DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm", ".txt", ".rtf", ".odt", ".ods", ".odp",
    ".csv", ".hwp", ".hwpx",
}

IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff",
    ".webp", ".ico", ".svg",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".msi", ".com",
}

SCRIPT_EXTENSIONS = {
    ".js", ".jse", ".ps1", ".psm1", ".vbs", ".vbe", ".bat", ".cmd",
    ".sh", ".bash", ".py", ".pl", ".rb", ".php", ".php3", ".php4",
    ".php5", ".phtml", ".jsp", ".jspx", ".asp", ".aspx", ".cgi",
}

MACRO_DOCUMENT_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm",
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".tar.gz", ".tar.bz2", ".tar.xz",
}

KNOWN_EXTENSIONS = (
    DOCUMENT_EXTENSIONS
    | IMAGE_EXTENSIONS
    | EXECUTABLE_EXTENSIONS
    | SCRIPT_EXTENSIONS
    | MACRO_DOCUMENT_EXTENSIONS
    | ARCHIVE_EXTENSIONS
)

# 확장자 -> category
# 명세의 대표 category(document/image/archive/executable)를 유지하고
# script/macro도 구분한다.
EXTENSION_CATEGORY = {}

for _ext in DOCUMENT_EXTENSIONS:
    EXTENSION_CATEGORY[_ext] = "document"
for _ext in IMAGE_EXTENSIONS:
    EXTENSION_CATEGORY[_ext] = "image"
for _ext in EXECUTABLE_EXTENSIONS:
    EXTENSION_CATEGORY[_ext] = "executable"
for _ext in SCRIPT_EXTENSIONS:
    EXTENSION_CATEGORY[_ext] = "script"
for _ext in MACRO_DOCUMENT_EXTENSIONS:
    EXTENSION_CATEGORY[_ext] = "document"
for _ext in ARCHIVE_EXTENSIONS:
    EXTENSION_CATEGORY[_ext] = "archive"


# Magic Bytes -> (format_name, mime_type, representative_extensions)
MAGIC_SIGNATURES = {
    b"%PDF-": ("pdf", "application/pdf", {".pdf"}),
    b"\x4d\x5a": ("pe", "application/vnd.microsoft.portable-executable",
                  {".exe", ".dll", ".sys", ".scr", ".com"}),
    b"\x89PNG\r\n\x1a\n": ("png", "image/png", {".png"}),
    b"\xff\xd8\xff": ("jpeg", "image/jpeg", {".jpg", ".jpeg"}),
    b"GIF87a": ("gif", "image/gif", {".gif"}),
    b"GIF89a": ("gif", "image/gif", {".gif"}),
    b"PK\x03\x04": ("zip", "application/zip", {".zip"}),
    b"PK\x05\x06": ("zip", "application/zip", {".zip"}),
    b"PK\x07\x08": ("zip", "application/zip", {".zip"}),
    b"Rar!\x1a\x07\x00": ("rar", "application/vnd.rar", {".rar"}),
    b"Rar!\x1a\x07\x01\x00": ("rar", "application/vnd.rar", {".rar"}),
    b"\x37\x7a\xbc\xaf\x27\x1c": ("7z", "application/x-7z-compressed", {".7z"}),
    b"\x1f\x8b": ("gzip", "application/gzip", {".gz", ".tar.gz"}),
    b"BZh": ("bzip2", "application/x-bzip2", {".bz2", ".tar.bz2"}),
    b"\xfd7zXZ\x00": ("xz", "application/x-xz", {".xz", ".tar.xz"}),
}

# MIME -> extensions that are considered compatible.
MIME_EXTENSION_MAP = {
    "application/pdf": {".pdf"},
    "application/zip": {".zip"},
    "application/x-zip-compressed": {".zip"},
    "application/vnd.rar": {".rar"},
    "application/x-rar-compressed": {".rar"},
    "application/x-7z-compressed": {".7z"},
    "application/gzip": {".gz", ".tar.gz"},
    "application/x-gzip": {".gz", ".tar.gz"},
    "application/x-bzip2": {".bz2", ".tar.bz2"},
    "application/x-xz": {".xz", ".tar.xz"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/png": {".png"},
    "image/gif": {".gif"},
    "image/bmp": {".bmp"},
    "image/webp": {".webp"},
    "image/tiff": {".tif", ".tiff"},
    "application/vnd.microsoft.portable-executable":
        {".exe", ".dll", ".sys", ".scr", ".com"},
}

# 위험 문자열 탐지 패턴.
# 각 Feature는 "출현 횟수"를 저장한다.
SUSPICIOUS_COMMAND_PATTERNS = [
    r"\bpowershell(?:\.exe)?\b",
    r"\bcmd(?:\.exe)?\b",
    r"\bwget(?:\.exe)?\b",
]

EXECUTION_API_PATTERNS = [
    # PHP / 범용 스크립트 실행 함수
    r"\bsystem\s*\(",
    r"\bexec\s*\(",
    r"\bpassthru\s*\(",
    r"\bshell_exec\s*\(",
    r"\bpopen\s*\(",
    r"\bproc_open\s*\(",
    r"\bassert\s*\(",
    # Java/JSP 프로세스 실행
    r"\bRuntime\s*\.\s*(?:getRuntime\s*\(\s*\)\s*\.)?exec\s*\(",
    r"\bnew\s+ProcessBuilder\s*\(",
    # Windows API / 동적 코드 실행
    r"\bCreateProcess(?:A|W)?\s*\(",
    r"\bShellExecute(?:A|W)?\s*\(",
    r"\beval\s*\(",
    # Classic ASP에서 COM 객체를 통한 프로세스 실행 등에 사용
    r"\bServer\s*\.\s*CreateObject\s*\(",
]

NETWORK_API_PATTERNS = [
    r"\bconnect\s*\(",
    r"\bURLDownloadToFile(?:A|W)?\s*\(",
    r"\bWinHttpOpen\s*\(",
]

OBFUSCATION_PATTERNS = [
    r"\bfromCharCode\s*\(",
    r"\bbase64_decode\s*\(",
    r"\bgzinflate\s*\(",
    r"\bstr_rot13\s*\(",
    r"(?:0x[0-9a-fA-F]{2,}\s*,\s*){4,}0x[0-9a-fA-F]{2,}",
]

# 웹 요청에서 공격자가 제어할 수 있는 값을 읽는 대표 패턴.
# 외부 입력 자체는 정상 코드에도 흔하므로 별도 출력 Feature를 추가하지 않고,
# 기존 37개 구조를 유지한 채 suspicious_string_count에만 반영한다.
EXTERNAL_INPUT_PATTERNS = [
    # PHP superglobal
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[",
    # Java Servlet / JSP
    r"\brequest\s*\.\s*(?:getParameter|getParameterValues|getHeader|getCookies)\s*\(",
    # Classic ASP / ASP.NET
    r"\bRequest\s*\.\s*(?:Form|QueryString|Cookies|Params)\b",
    r"\bRequest\s*\(\s*[\"']",
    # Python 웹 프레임워크
    r"\brequest\s*\.\s*(?:args|form|json|values|files)\b",
    # Node.js / Express
    r"\breq\s*\.\s*(?:query|body|params|cookies)\b",
]

URL_PATTERN = re.compile(
    rb"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    rb"(?<![\d.])"
    rb"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    rb"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
    rb"(?![\d.])"
)

# 명세에서 최소 문자열 길이를 50 bytes로 둔 부분을 따른다.
BASE64_MIN_LENGTH = 50
BASE64_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9+/])"
    rb"[A-Za-z0-9+/]{50,}={0,2}"
    rb"(?![A-Za-z0-9+/])"
)

# 파일 내부에 나타난 대표적인 형식 시그니처.
# embedded_file_signature_count 계산에 사용한다.
EMBEDDED_SIGNATURES = {
    b"%PDF-",
    b"\x4d\x5a",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"PK\x03\x04",
    b"Rar!\x1a\x07\x00",
    b"Rar!\x1a\x07\x01\x00",
    b"\x37\x7a\xbc\xaf\x27\x1c",
}

# 확장자별 header entropy 계산 범위.
# 파일 시그니처와 초기 메타데이터/컨테이너 구조가 들어오는 범위를 기준으로
# 설정한다. 값은 Magic Bytes 자체의 길이가 아니라, header_entropy를 계산할
# 파일 앞부분의 최대 byte 수이다. 파일이 이보다 작으면 파일 전체를 사용한다.
HEADER_SIZE_MAP = {
    # 문서
    ".pdf": 1024,
    ".doc": 512,
    ".docx": 4096,
    ".docm": 4096,
    ".xls": 512,
    ".xlsx": 4096,
    ".xlsm": 4096,
    ".ppt": 512,
    ".pptx": 4096,
    ".pptm": 4096,
    ".txt": 4096,
    ".rtf": 1024,
    ".odt": 4096,
    ".ods": 4096,
    ".odp": 4096,
    ".csv": 4096,
    ".hwp": 512,
    ".hwpx": 4096,

    # 이미지
    ".jpg": 4096,
    ".jpeg": 4096,
    ".png": 64,
    ".gif": 64,
    ".bmp": 64,
    ".tif": 64,
    ".tiff": 64,
    ".webp": 64,
    ".ico": 64,
    ".svg": 4096,

    # 실행 파일
    ".exe": 4096,
    ".dll": 4096,
    ".sys": 4096,
    ".scr": 4096,
    ".msi": 512,
    ".com": 512,

    # 스크립트/소스 텍스트
    ".js": 4096,
    ".jse": 4096,
    ".ps1": 4096,
    ".psm1": 4096,
    ".vbs": 4096,
    ".vbe": 4096,
    ".bat": 4096,
    ".cmd": 4096,
    ".sh": 4096,
    ".bash": 4096,
    ".py": 4096,
    ".pl": 4096,
    ".rb": 4096,
    ".php": 4096,
    ".php3": 4096,
    ".php4": 4096,
    ".php5": 4096,
    ".phtml": 4096,
    ".jsp": 4096,
    ".jspx": 4096,
    ".asp": 4096,
    ".aspx": 4096,
    ".cgi": 4096,

    # 압축/컨테이너
    ".zip": 4096,
    ".rar": 64,
    ".7z": 64,
    ".tar": 512,
    ".gz": 64,
    ".bz2": 64,
    ".xz": 64,
    ".tar.gz": 64,
    ".tar.bz2": 64,
    ".tar.xz": 64,
}

DEFAULT_HEADER_SIZE = 4096

# KNOWN_EXTENSIONS와 HEADER_SIZE_MAP이 서로 어긋나는 것을 조기에 탐지한다.
_MISSING_HEADER_SIZE_EXTENSIONS = KNOWN_EXTENSIONS - HEADER_SIZE_MAP.keys()
if _MISSING_HEADER_SIZE_EXTENSIONS:
    missing = ", ".join(sorted(_MISSING_HEADER_SIZE_EXTENSIONS))
    raise RuntimeError(f"HEADER_SIZE_MAP에 없는 확장자: {missing}")

# Archive bomb 판정용 기준.
# 실제 프로젝트에서는 데이터셋 특성에 맞춰 별도 설정 파일로 분리하는 것을 권장.
ARCHIVE_MAX_ENTRIES = 100_000
ARCHIVE_MAX_UNCOMPRESSED_BYTES = 1_000_000_000  # 1 GB
ARCHIVE_MAX_COMPRESSION_RATIO = 100.0

# 재귀 압축 분석 안전 제한.
MAX_ARCHIVE_DEPTH_TO_INSPECT = 5
MAX_NESTED_ARCHIVE_BYTES_TO_READ = 32 * 1024 * 1024


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _read_head(file_path: Path, size: int = 64) -> bytes:
    try:
        with file_path.open("rb") as f:
            return f.read(size)
    except OSError:
        return b""


def _iter_file_chunks(
    file_path: Path,
    chunk_size: int = 1024 * 1024,
) -> Iterable[bytes]:
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def _count_regex_bytes(data: bytes, pattern: re.Pattern[bytes]) -> int:
    return len(pattern.findall(data))


def _count_regex_text(text: str, patterns: Iterable[str]) -> int:
    count = 0
    for pattern in patterns:
        count += len(re.findall(pattern, text, flags=re.IGNORECASE))
    return count


def _count_distinct_regex_text(text: str, patterns: Iterable[str]) -> int:
    """겹치는 패턴이 같은 코드 조각을 중복 집계하지 않도록 센다."""
    combined = "|".join(f"(?:{pattern})" for pattern in patterns)
    if not combined:
        return 0
    return len(re.findall(combined, text, flags=re.IGNORECASE))


def _is_unicode_control_char(ch: str) -> bool:
    # Unicode format/control characters.
    # 특히 RTL/LTR 등의 화면 표시 조작에 사용될 수 있는 문자 포함.
    return (
        ch in {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066",
               "\u2067", "\u2069", "\u200e", "\u200f"}
        or (ord(ch) < 32 and ch not in "\t\n\r")
        or (0x7F <= ord(ch) <= 0x9F)
    )


def _normalized_suffixes(filename: str) -> list[str]:
    """
    파일명에서 '알려진 확장자'만 추출한다.

    예:
        report.pdf.exe -> [".pdf", ".exe"]
        sample.tar.gz  -> [".tar.gz"]  (복합 확장자를 하나로 취급)
    """
    name = Path(filename).name
    lower = name.lower()

    # 긴 복합 확장자를 우선 인식한다.
    composite = sorted(
        (ext for ext in KNOWN_EXTENSIONS if ext.count(".") >= 2),
        key=len,
        reverse=True,
    )

    composite_suffix = ""
    remainder = lower

    # 예: sample.tar.gz
    for ext in composite:
        if remainder.endswith(ext):
            composite_suffix = ext
            remainder = remainder[: -len(ext)]
            break

    # 나머지 부분에서 일반 확장자를 추출한다.
    suffixes: list[str] = []
    parts = remainder.split(".")
    if len(parts) > 1:
        for part in parts[1:]:
            ext = "." + part
            if ext in KNOWN_EXTENSIONS:
                suffixes.append(ext)

    if composite_suffix:
        suffixes.append(composite_suffix)

    return suffixes


def _last_known_extension(filename: str) -> str:
    suffixes = _normalized_suffixes(filename)
    return suffixes[-1] if suffixes else ""


def _detect_extension_category(filename: str) -> str:
    suffixes = _normalized_suffixes(filename)
    if not suffixes:
        return "unknown"

    # 가장 마지막에 표시되는 확장자를 기준으로 분류.
    ext = suffixes[-1]
    return EXTENSION_CATEGORY.get(ext, "unknown")


def _get_magic_info(data: bytes) -> Tuple[Optional[str], Optional[str], set[str]]:
    best = None
    for signature, info in MAGIC_SIGNATURES.items():
        if data.startswith(signature):
            if best is None or len(signature) > len(best[0]):
                best = (signature, info)

    if best is None:
        return None, None, set()

    _, (format_name, mime_type, extensions) = best
    return format_name, mime_type, extensions


def _magic_matches_extension(filename: str, magic_extensions: set[str]) -> int:
    final_extension = _last_known_extension(filename)
    if not final_extension or not magic_extensions:
        return 0

    # 사용자에게 표시되는 마지막 확장자와 실제 형식을 비교.
    return int(final_extension in magic_extensions)


def _mime_matches_extension(filename: str, mime_type: Optional[str]) -> int:
    if not mime_type:
        return 0

    final_extension = _last_known_extension(filename)
    if not final_extension:
        return 0

    mime = mime_type.lower().split(";", 1)[0].strip()

    if mime in MIME_EXTENSION_MAP:
        return int(final_extension in MIME_EXTENSION_MAP[mime])

    # python-magic이 특정 MIME을 반환하더라도 표에 없는 경우에는
    # mimetypes의 일반적인 추정을 보조적으로 사용한다.
    guessed, _ = mimetypes.guess_type("x" + final_extension)
    if guessed and guessed == mime:
        return 1

    return 0


def _detect_mime(file_path: Path) -> Optional[str]:
    if magic is not None:
        try:
            return magic.from_file(str(file_path), mime=True)
        except Exception:
            pass

    # Magic Bytes fallback.
    head = _read_head(file_path, 64)
    _, mime_type, _ = _get_magic_info(head)
    if mime_type:
        return mime_type

    guessed, _ = mimetypes.guess_type(file_path.name)
    return guessed


# ---------------------------------------------------------------------------
# 1. 파일명 / 기본 정보
# ---------------------------------------------------------------------------

def analyze_filename(filename: str) -> Dict[str, Any]:
    name = Path(filename).name
    suffixes = _normalized_suffixes(name)

    extension_count = len(suffixes)
    has_double_extension = int(extension_count >= 2)

    last_ext = _last_known_extension(name)
    has_uppercase_extension = int(
        bool(last_ext) and any(ch.isupper() for ch in name.rsplit(".", 1)[-1])
    )

    has_unicode_control_char = int(any(_is_unicode_control_char(ch) for ch in name))

    # 명세: 점과 밑줄도 특수문자로 센다.
    # 여기서는 영문/숫자/한글을 일반 문자로 보고 나머지를 특수문자로 계산.
    if len(name) == 0:
        special_char_ratio = 0.0
    else:
        special_count = sum(
            1 for ch in name
            if not (ch.isalnum())
        )
        special_char_ratio = special_count / len(name)

    return {
        "filename_length": len(name),
        "extension_count": extension_count,
        "has_double_extension": has_double_extension,
        "has_uppercase_extension": has_uppercase_extension,
        "has_unicode_control_char": has_unicode_control_char,
        "special_char_ratio": special_char_ratio,
        "extension_category": _detect_extension_category(name),
        "is_executable_extension": int(
            any(ext in EXECUTABLE_EXTENSIONS for ext in suffixes)
        ),
        "is_script_extension": int(
            any(ext in SCRIPT_EXTENSIONS for ext in suffixes)
        ),
        "is_macro_document": int(
            any(ext in MACRO_DOCUMENT_EXTENSIONS for ext in suffixes)
        ),
        "is_archive_extension": int(
            any(ext in ARCHIVE_EXTENSIONS for ext in suffixes)
        ),
        "is_unknown_extension": int(extension_count == 0),
    }


# ---------------------------------------------------------------------------
# 2. Magic Bytes / MIME
# ---------------------------------------------------------------------------

def analyze_file_type(
    file_path: str | Path,
    filename: Optional[str] = None,
    claimed_mime: Optional[str] = None,
) -> Dict[str, Any]:
    path = Path(file_path)
    name = filename or path.name

    head = _read_head(path, 64)
    _, detected_magic_mime, magic_extensions = _get_magic_info(head)

    magic_bytes_known = int(detected_magic_mime is not None)
    magic_bytes_valid = (
        _magic_matches_extension(name, magic_extensions)
        if magic_bytes_known
        else 0
    )

    detected_mime = _detect_mime(path)

    extension_mime_mismatch = (
        int(
            bool(_normalized_suffixes(name))
            and detected_mime is not None
            and not _mime_matches_extension(name, detected_mime)
        )
    )

    if claimed_mime is None:
        # Content-Type이 제공되지 않은 경우와 정상 일치(0)를 구분한다.
        claimed_mime_mismatch = None
    else:
        claimed = claimed_mime.lower().split(";", 1)[0].strip()
        actual = (detected_mime or "").lower().split(";", 1)[0].strip()
        claimed_mime_mismatch = int(bool(actual) and claimed != actual)

    return {
        "magic_bytes_known": magic_bytes_known,
        "magic_bytes_valid": magic_bytes_valid,
        "extension_mime_mismatch": extension_mime_mismatch,
        "claimed_mime_mismatch": claimed_mime_mismatch,
    }


# ---------------------------------------------------------------------------
# 3. 바이트 통계
# ---------------------------------------------------------------------------

def _entropy_from_counter(counter: Counter[int], total: int) -> float:
    if total <= 0:
        return 0.0

    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def calculate_byte_statistics(
    file_path: str | Path,
    header_size: int,
) -> Dict[str, Any]:
    path = Path(file_path)

    counter: Counter[int] = Counter()
    header_counter: Counter[int] = Counter()

    total = 0
    printable = 0
    null_bytes = 0
    header_total = 0

    try:
        for chunk in _iter_file_chunks(path):
            total += len(chunk)
            counter.update(chunk)
            printable += sum(
                1 for b in chunk
                if 32 <= b <= 126
            )
            null_bytes += chunk.count(0)

            if header_total < header_size:
                header_chunk = chunk[: header_size - header_total]
                header_counter.update(header_chunk)
                header_total += len(header_chunk)

    except OSError:
        return {
            "byte_entropy": 0.0,
            "header_entropy": 0.0,
            "printable_ratio": 0.0,
            "null_byte_ratio": 0.0,
            "unique_byte_count": 0,
        }

    return {
        "byte_entropy": _entropy_from_counter(counter, total),
        "header_entropy": _entropy_from_counter(header_counter, header_total),
        "printable_ratio": printable / total if total else 0.0,
        "null_byte_ratio": null_bytes / total if total else 0.0,
        "unique_byte_count": len(counter),
    }


# ---------------------------------------------------------------------------
# 4. 파일 내부 위험 문자열
# ---------------------------------------------------------------------------

def _read_text_for_static_scan(
    file_path: Path,
    max_bytes: int = 64 * 1024 * 1024,
) -> str:
    """
    텍스트 분석용으로만 읽는다.
    파일을 실행하지 않는다.

    max_bytes를 넘는 파일은 앞부분만 분석한다.
    """
    try:
        with file_path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="ignore")
    except OSError:
        return ""


def _count_embedded_signatures(file_path: Path) -> int:
    """
    파일 시작(offset=0)의 대표 Magic Bytes는 제외하고,
    파일 내부(offset>0)에 나타나는 알려진 시그니처의 출현 횟수를 센다.
    """
    try:
        data = b"".join(_iter_file_chunks(file_path))
    except OSError:
        return 0

    count = 0

    for signature in EMBEDDED_SIGNATURES:
        start = 1
        while True:
            idx = data.find(signature, start)
            if idx == -1:
                break
            count += 1
            start = idx + 1

    return count


def analyze_content(
    file_path: str | Path,
) -> Dict[str, Any]:
    path = Path(file_path)

    # 정적 문자열 탐지.
    # 일반적인 스크립트/바이너리 샘플에서 사람이 읽을 수 있는 문자열을
    # 분석하기 위해 latin-1로 변환한다.
    try:
        with path.open("rb") as f:
            data = f.read(64 * 1024 * 1024)
    except OSError:
        data = b""

    text = data.decode("latin-1", errors="ignore")

    url_count = _count_regex_bytes(data, URL_PATTERN)
    ip_address_count = _count_regex_bytes(data, IP_PATTERN)
    base64_candidate_count = _count_regex_bytes(data, BASE64_PATTERN)

    suspicious_command_count = _count_regex_text(
        text,
        SUSPICIOUS_COMMAND_PATTERNS,
    )
    execution_api_count = _count_distinct_regex_text(
        text,
        EXECUTION_API_PATTERNS,
    )
    network_api_count = _count_regex_text(
        text,
        NETWORK_API_PATTERNS,
    )

    # 긴 Base64 후보도 난독화 패턴에 포함.
    obfuscation_pattern_count = (
        base64_candidate_count
        + _count_regex_text(text, OBFUSCATION_PATTERNS)
    )

    # 외부 입력은 정상 웹 애플리케이션에도 자주 나타나므로 독립 출력값으로
    # 악성도를 과도하게 높이지 않고, 전체 위험 문자열 집계에만 포함한다.
    external_input_count = _count_distinct_regex_text(
        text,
        EXTERNAL_INPUT_PATTERNS,
    )

    # 기존 37개 Feature 구조를 유지하면서 웹셸 외부 입력 단서까지 합산한다.
    suspicious_string_count = (
        suspicious_command_count
        + execution_api_count
        + network_api_count
        + obfuscation_pattern_count
        + external_input_count
    )

    return {
        "url_count": url_count,
        "ip_address_count": ip_address_count,
        "base64_candidate_count": base64_candidate_count,
        "suspicious_command_count": suspicious_command_count,
        "execution_api_count": execution_api_count,
        "network_api_count": network_api_count,
        "obfuscation_pattern_count": obfuscation_pattern_count,
        "suspicious_string_count": suspicious_string_count,
        "embedded_file_signature_count": _count_embedded_signatures(path),
    }


# ---------------------------------------------------------------------------
# 5. Archive 분석
# ---------------------------------------------------------------------------

def _archive_type_from_extension(filename: str) -> Optional[str]:
    suffixes = _normalized_suffixes(filename)
    if not suffixes:
        return None

    if any(ext in {".zip"} for ext in suffixes):
        return "zip"
    if any(ext in {".rar"} for ext in suffixes):
        return "rar"
    if any(ext in {".7z"} for ext in suffixes):
        return "7z"
    return None


def _archive_bomb_flag(
    entry_count: int,
    total_uncompressed_size: int,
    compression_ratio: float,
) -> int:
    return int(
        entry_count > ARCHIVE_MAX_ENTRIES
        or total_uncompressed_size > ARCHIVE_MAX_UNCOMPRESSED_BYTES
        or compression_ratio > ARCHIVE_MAX_COMPRESSION_RATIO
    )


def _zip_stats_from_bytes(
    data: bytes,
    depth: int,
) -> Tuple[int, int, int, int, float, int]:
    """
    ZIP bytes를 받아 archive feature를 계산한다.

    반환:
        entry_count,
        executable_count,
        script_count,
        max_depth,
        compression_ratio,
        bomb_suspected
    """
    try:
        import io

        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            infos = zf.infolist()

            entry_count = len(infos)
            executable_count = 0
            script_count = 0
            total_uncompressed = 0
            total_compressed = 0
            max_depth = depth

            nested_archives: list[tuple[str, int]] = []

            for info in infos:
                if info.is_dir():
                    continue

                name = info.filename
                suffixes = _normalized_suffixes(name)

                if any(ext in EXECUTABLE_EXTENSIONS for ext in suffixes):
                    executable_count += 1

                if any(ext in SCRIPT_EXTENSIONS for ext in suffixes):
                    script_count += 1

                total_uncompressed += max(0, info.file_size)
                total_compressed += max(0, info.compress_size)

                nested_type = _archive_type_from_extension(name)
                if nested_type and depth < MAX_ARCHIVE_DEPTH_TO_INSPECT:
                    nested_archives.append((name, info.file_size))

            archive_size = len(data)
            ratio = (
                total_uncompressed / archive_size
                if archive_size > 0
                else 0.0
            )

            bomb = _archive_bomb_flag(
                entry_count,
                total_uncompressed,
                ratio,
            )

            # 중첩 압축의 최대 깊이를 추정.
            for nested_name, nested_size in nested_archives:
                # 너무 큰 nested archive는 읽지 않는다.
                if nested_size > MAX_NESTED_ARCHIVE_BYTES_TO_READ:
                    continue

                try:
                    nested_data = zf.read(nested_name)
                except Exception:
                    continue

                nested_type = _archive_type_from_extension(nested_name)
                if nested_type == "zip":
                    (
                        nested_entries,
                        nested_exes,
                        nested_scripts,
                        nested_depth,
                        nested_ratio,
                        nested_bomb,
                    ) = _zip_stats_from_bytes(nested_data, depth + 1)

                    # 내부 통계도 합산.
                    entry_count += nested_entries
                    executable_count += nested_exes
                    script_count += nested_scripts
                    max_depth = max(max_depth, nested_depth)
                    bomb = int(bomb or nested_bomb)

            return (
                entry_count,
                executable_count,
                script_count,
                max_depth,
                ratio,
                bomb,
            )

    except (zipfile.BadZipFile, OSError, ValueError):
        return 0, 0, 0, depth, 0.0, 0


def _zip_stats(file_path: Path) -> Tuple[int, int, int, int, float, int]:
    try:
        data = file_path.read_bytes()
    except OSError:
        return 0, 0, 0, 0, 0.0, 0

    return _zip_stats_from_bytes(data, depth=0)


def _rar_stats(file_path: Path) -> Tuple[int, int, int, int, float, int]:
    """
    RAR 분석은 rarfile가 설치된 경우에만 수행한다.
    rarfile는 환경에 따라 외부 unrar/bsdtar 프로그램이 필요할 수 있다.
    """
    if rarfile is None:
        return 0, 0, 0, 0, 0.0, 0

    try:
        with rarfile.RarFile(str(file_path)) as rf:
            infos = rf.infolist()
            entry_count = len(infos)
            executable_count = 0
            script_count = 0
            total_uncompressed = 0

            for info in infos:
                if getattr(info, "isdir", lambda: False)():
                    continue

                name = getattr(info, "filename", "")
                suffixes = _normalized_suffixes(name)

                if any(ext in EXECUTABLE_EXTENSIONS for ext in suffixes):
                    executable_count += 1
                if any(ext in SCRIPT_EXTENSIONS for ext in suffixes):
                    script_count += 1

                total_uncompressed += max(
                    0,
                    int(getattr(info, "file_size", 0)),
                )

            archive_size = file_path.stat().st_size
            ratio = (
                total_uncompressed / archive_size
                if archive_size > 0
                else 0.0
            )

            bomb = _archive_bomb_flag(
                entry_count,
                total_uncompressed,
                ratio,
            )

            return (
                entry_count,
                executable_count,
                script_count,
                0,
                ratio,
                bomb,
            )

    except Exception:
        return 0, 0, 0, 0, 0.0, 0


def _seven_zip_stats(file_path: Path) -> Tuple[int, int, int, int, float, int]:
    """
    7z 분석은 py7zr가 설치된 경우에만 수행한다.
    """
    if py7zr is None:
        return 0, 0, 0, 0, 0.0, 0

    try:
        with py7zr.SevenZipFile(str(file_path), mode="r") as archive:
            names = archive.getnames()

            entry_count = len(names)
            executable_count = 0
            script_count = 0

            for name in names:
                suffixes = _normalized_suffixes(name)
                if any(ext in EXECUTABLE_EXTENSIONS for ext in suffixes):
                    executable_count += 1
                if any(ext in SCRIPT_EXTENSIONS for ext in suffixes):
                    script_count += 1

            # py7zr의 API/버전에 따라 전체 unpacked size를 직접 얻는 방식이
            # 달라질 수 있으므로, 여기서는 파일 내부 항목 수와 위험 확장자를
            # 안정적으로 제공하고 압축률은 0으로 둔다.
            return (
                entry_count,
                executable_count,
                script_count,
                0,
                0.0,
                int(entry_count > ARCHIVE_MAX_ENTRIES),
            )

    except Exception:
        return 0, 0, 0, 0, 0.0, 0


def analyze_archive(
    file_path: str | Path,
    filename: Optional[str] = None,
) -> Dict[str, Any]:
    path = Path(file_path)
    name = filename or path.name

    archive_type = _archive_type_from_extension(name)

    if archive_type is None:
        return {
            "archive_entry_count": 0,
            "executable_entry_count": 0,
            "script_entry_count": 0,
            "archive_depth": 0,
            "compression_ratio": 0.0,
            "archive_bomb_suspected": 0,
        }

    if archive_type == "zip":
        (
            entry_count,
            executable_count,
            script_count,
            depth,
            ratio,
            bomb,
        ) = _zip_stats(path)

    elif archive_type == "rar":
        (
            entry_count,
            executable_count,
            script_count,
            depth,
            ratio,
            bomb,
        ) = _rar_stats(path)

    elif archive_type == "7z":
        (
            entry_count,
            executable_count,
            script_count,
            depth,
            ratio,
            bomb,
        ) = _seven_zip_stats(path)

    else:
        # tar/gz/bz2/xz는 명세상 archive extension이지만,
        # 현재 구현에서는 ZIP/RAR/7z 내부 항목 분석을 우선한다.
        entry_count = 0
        executable_count = 0
        script_count = 0
        depth = 0
        ratio = 0.0
        bomb = 0

    return {
        "archive_entry_count": entry_count,
        "executable_entry_count": executable_count,
        "script_entry_count": script_count,
        "archive_depth": depth,
        "compression_ratio": ratio,
        "archive_bomb_suspected": bomb,
    }


# ---------------------------------------------------------------------------
# 6. 전체 전처리
# ---------------------------------------------------------------------------

FEATURE_ORDER = [
    "file_size",
    "filename_length",
    "extension_count",
    "has_double_extension",
    "has_uppercase_extension",
    "has_unicode_control_char",
    "special_char_ratio",
    "extension_category",
    "is_executable_extension",
    "is_script_extension",
    "is_macro_document",
    "is_archive_extension",
    "is_unknown_extension",
    "magic_bytes_known",
    "magic_bytes_valid",
    "extension_mime_mismatch",
    "claimed_mime_mismatch",
    "embedded_file_signature_count",
    "byte_entropy",
    "header_entropy",
    "printable_ratio",
    "null_byte_ratio",
    "unique_byte_count",
    "url_count",
    "ip_address_count",
    "base64_candidate_count",
    "suspicious_command_count",
    "execution_api_count",
    "network_api_count",
    "obfuscation_pattern_count",
    "suspicious_string_count",
    "archive_entry_count",
    "executable_entry_count",
    "script_entry_count",
    "archive_depth",
    "compression_ratio",
    "archive_bomb_suspected",
]


def preprocess(
    file_path: str | Path,
    claimed_mime: Optional[str] = None,
) -> Dict[str, Any]:
    """
    파일 하나를 입력받아 Output Feature 명세의 37개 Feature를 반환한다.

    Args:
        file_path:
            분석할 실제 파일 경로.
        claimed_mime:
            업로드 당시 HTTP Content-Type.
            모르는 경우 None.

    Returns:
        FEATURE_ORDER 순서의 Feature Dictionary.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {path}")

    filename = path.name

    try:
        file_size = path.stat().st_size
    except OSError:
        file_size = 0

    filename_features = analyze_filename(filename)
    file_type_features = analyze_file_type(
        path,
        filename=filename,
        claimed_mime=claimed_mime,
    )
    content_features = analyze_content(path)

    header_size = HEADER_SIZE_MAP.get(
        _last_known_extension(filename),
        DEFAULT_HEADER_SIZE,
    )

    byte_features = calculate_byte_statistics(
        path,
        header_size=header_size,
    )

    archive_features = analyze_archive(
        path,
        filename=filename,
    )

    features: Dict[str, Any] = {
        "file_size": file_size,
    }

    features.update(filename_features)
    features.update(file_type_features)
    features.update(content_features)
    features.update(byte_features)
    features.update(archive_features)

    # 누락/순서 오류를 조기에 잡기 위해 명세와 정확히 일치하는지 확인.
    missing = [name for name in FEATURE_ORDER if name not in features]
    if missing:
        raise RuntimeError(f"Feature 누락: {missing}")

    return {name: features[name] for name in FEATURE_ORDER}


def preprocess_many(
    file_paths: Iterable[str | Path],
    claimed_mimes: Optional[Dict[str, str]] = None,
) -> list[Dict[str, Any]]:
    """
    여러 파일을 분석한다.

    claimed_mimes:
        {str(file_path): "image/jpeg"} 형태의 선택적 Content-Type 정보.
    """
    results = []

    for file_path in file_paths:
        key = str(file_path)
        claimed_mime = claimed_mimes.get(key) if claimed_mimes else None
        results.append(
            preprocess(
                file_path,
                claimed_mime=claimed_mime,
            )
        )

    return results


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Output Feature 명세 기반 정적 파일 Feature 추출기"
    )
    parser.add_argument("file", help="분석할 파일 경로")
    parser.add_argument(
        "--claimed-mime",
        default=None,
        help="업로드 당시 Content-Type (예: image/jpeg)",
    )

    args = parser.parse_args()

    result = preprocess(
        args.file,
        claimed_mime=args.claimed_mime,
    )

    print(json.dumps(result, ensure_ascii=False, indent=2))