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