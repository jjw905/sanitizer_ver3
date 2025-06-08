import os
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import IndirectObject
import config


def safe_get(obj):
    return obj.get_object() if isinstance(obj, IndirectObject) else obj


def find_javascript_keys(obj, found=None, path=""):
    if found is None:
        found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = str(k)
            full_path = f"{path}/{key_str}" if path else key_str
            full_path = full_path.replace("//", "/")
            if key_str in ["/JavaScript", "/JS", "/OpenAction", "/AA", "/URI", "/Launch", "/SubmitForm"]:
                found.append(full_path)
            find_javascript_keys(v, found, full_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            find_javascript_keys(item, found, f"{path}[{i}]")
    return found


def extract_pdf_javascript(file_path: str) -> dict:
    """PDF에서 JavaScript 내용 추출"""
    js_contents = {}

    try:
        reader = PdfReader(file_path)

        # Names 카탈로그에서 JavaScript 추출
        if "/Root" in reader.trailer:
            root = safe_get(reader.trailer["/Root"])

            # Names 딕셔너리 확인
            if "/Names" in root:
                names = safe_get(root["/Names"])
                if "/JavaScript" in names:
                    js_tree = safe_get(names["/JavaScript"])
                    if "/Names" in js_tree:
                        js_names = safe_get(js_tree["/Names"])
                        # JavaScript 이름/내용 쌍 추출
                        for i in range(0, len(js_names), 2):
                            if i + 1 < len(js_names):
                                name = str(js_names[i])
                                js_obj = safe_get(js_names[i + 1])
                                if "/JS" in js_obj:
                                    js_code = safe_get(js_obj["/JS"])
                                    if hasattr(js_code, 'get_data'):
                                        js_contents[name] = js_code.get_data().decode('utf-8', errors='ignore')
                                    else:
                                        js_contents[name] = str(js_code)

            # OpenAction에서 JavaScript 확인
            if "/OpenAction" in root:
                action = safe_get(root["/OpenAction"])
                if isinstance(action, dict) and "/JS" in action:
                    js_code = safe_get(action["/JS"])
                    if hasattr(js_code, 'get_data'):
                        js_contents["OpenAction"] = js_code.get_data().decode('utf-8', errors='ignore')
                    else:
                        js_contents["OpenAction"] = str(js_code)

            # 페이지별 JavaScript 확인
            for page_num, page in enumerate(reader.pages):
                page_obj = page.get_object()
                if "/AA" in page_obj:  # Additional Actions
                    aa = safe_get(page_obj["/AA"])
                    for trigger, action in aa.items():
                        if isinstance(action, dict) and "/JS" in action:
                            js_code = safe_get(action["/JS"])
                            if hasattr(js_code, 'get_data'):
                                js_contents[f"Page{page_num}_{trigger}"] = js_code.get_data().decode('utf-8',
                                                                                                     errors='ignore')
                            else:
                                js_contents[f"Page{page_num}_{trigger}"] = str(js_code)

                # Annotations에서 JavaScript 확인
                if "/Annots" in page_obj:
                    annots = safe_get(page_obj["/Annots"])
                    for annot_ref in annots:
                        annot = safe_get(annot_ref)
                        if isinstance(annot, dict) and "/A" in annot:
                            action = safe_get(annot["/A"])
                            if isinstance(action, dict) and "/JS" in action:
                                js_code = safe_get(action["/JS"])
                                if hasattr(js_code, 'get_data'):
                                    js_contents[f"Page{page_num}_Annotation"] = js_code.get_data().decode('utf-8',
                                                                                                          errors='ignore')
                                else:
                                    js_contents[f"Page{page_num}_Annotation"] = str(js_code)

    except Exception as e:
        print(f"JavaScript 추출 중 오류: {e}")

    return js_contents

def remove_javascript_recursive(obj, removed_keys):
    """재귀적으로 JavaScript 관련 키 제거"""
    if isinstance(obj, dict):
        keys_to_remove = []
        for key in obj:
            if str(key) in ["/JavaScript", "/JS", "/OpenAction", "/AA", "/URI", "/Launch", "/SubmitForm"]:
                keys_to_remove.append(key)
                removed_keys.append(str(key))
            else:
                remove_javascript_recursive(obj.get(key), removed_keys)
        for key in keys_to_remove:
            del obj[key]
    elif isinstance(obj, list):
        for item in obj:
            remove_javascript_recursive(item, removed_keys)

def sanitize_pdf(file_path: str, output_dir: str = None) -> tuple[str, list[str]]:
    """PDF 파일에서 잠재적으로 위험한 요소(JavaScript, 자동 실행 등)를 제거"""
    if output_dir is None:
        output_dir = config.DIRECTORIES['sanitized_output']

    filename = os.path.splitext(os.path.basename(file_path))[0]
    clean_file = os.path.join(output_dir, f"{filename}_clean.pdf")

    removed_keys = []

    try:
        reader = PdfReader(file_path)
        writer = PdfWriter()

        # 모든 페이지를 새 writer에 추가
        for page in reader.pages:
            writer.add_page(page)

        # 문서의 루트(Root) 객체에서 재귀적으로 위험한 키워드 제거
        # PyPDF2 4.x.x 버전 호환성을 위해 _root가 아닌 trailer 사용
        if "/Root" in writer._trailer:
            root = writer._trailer["/Root"]
            remove_javascript_recursive(root, removed_keys)

        os.makedirs(output_dir, exist_ok=True)
        with open(clean_file, "wb") as f:
            writer.write(f)

    except Exception as e:
        print(f"PDF 무해화 중 오류 발생: {e}")
        return file_path, []

    # 중복 제거 후 반환
    return clean_file, list(set(removed_keys))