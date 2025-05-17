import os
import shutil
import zipfile
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML

def is_macro_present(file_path):
    vbaparser = VBA_Parser(file_path)
    if vbaparser.detect_vba_macros():
        print("⚠️ 매크로가 포함된 문서입니다.")
        return True
    print("✅ 매크로가 포함되어 있지 않습니다.")
    return False

def remove_macro_from_docx(file_path):
    if not zipfile.is_zipfile(file_path):
        print("❌ 지원하지 않는 형식입니다. docx/docm 파일만 가능합니다.")
        return None

    temp_dir = "temp_unzip"
    shutil.rmtree(temp_dir, ignore_errors=True)
    os.makedirs(temp_dir, exist_ok=True)

    # 압축 해제
    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    # 매크로 파일 삭제
    vba_path = os.path.join(temp_dir, "word", "vbaProject.bin")
    if os.path.exists(vba_path):
        os.remove(vba_path)
        print("🧹 vbaProject.bin 제거 완료")

    # 재압축
    clean_file = f"{os.path.splitext(file_path)[0]}_clean.docx"
    with zipfile.ZipFile(clean_file, 'w') as zip_out:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, temp_dir)
                zip_out.write(abs_path, rel_path)

    shutil.rmtree(temp_dir)
    print(f"✅ 무해화된 문서 생성 완료: {clean_file}")
    return clean_file
