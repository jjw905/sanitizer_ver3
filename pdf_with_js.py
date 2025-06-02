# pdf_with_js.py
from PyPDF2 import PdfWriter

writer = PdfWriter()
writer.add_blank_page(width=300, height=300)
writer.add_js("app.alert('PDF 자바스크립트 테스트');")
with open("test_js.pdf", "wb") as f:
    writer.write(f)