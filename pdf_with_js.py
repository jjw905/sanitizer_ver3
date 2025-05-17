# pdf_with_js.py
from PyPDF2 import PdfWriter

writer = PdfWriter()
writer.add_blank_page(width=200, height=200)

# JavaScript 삽입 (의도적으로 위험한 건 아님)
js = """
app.alert('This is a test JavaScript in PDF!');
"""

writer.add_js(js)
with open("test_with_js.pdf", "wb") as f:
    writer.write(f)
