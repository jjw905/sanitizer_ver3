# utils/pdf_reconstructor.py - PDF 문서 콘텐츠 재조립

import os
from PyPDF2 import PdfReader
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from PIL import Image
import io
import tempfile
import config


def reconstruct_pdf_document(file_path: str, output_dir: str = None) -> tuple[str, dict]:
    """PDF에서 안전한 콘텐츠만 추출하여 재조립"""
    if output_dir is None:
        output_dir = config.DIRECTORIES['sanitized_output']

    file_name = os.path.splitext(os.path.basename(file_path))[0]
    extracted_content = {'text': '', 'pages': 0, 'images': 0}

    try:
        # 원본 PDF 읽기
        reader = PdfReader(file_path)
        num_pages = len(reader.pages)
        extracted_content['pages'] = num_pages

        # 텍스트와 이미지 추출
        all_text = []
        extracted_images = []

        for page_num, page in enumerate(reader.pages):
            # 텍스트 추출
            try:
                page_text = page.extract_text()
                if page_text:
                    all_text.append(f"--- Page {page_num + 1} ---")
                    all_text.append(page_text.strip())
                    all_text.append("")
            except:
                pass

            # 이미지 추출 시도
            try:
                if '/XObject' in page['/Resources']:
                    xObject = page['/Resources']['/XObject'].get_object()

                    for obj in xObject:
                        if xObject[obj]['/Subtype'] == '/Image':
                            try:
                                # 이미지 데이터 추출
                                size = (xObject[obj]['/Width'], xObject[obj]['/Height'])
                                data = xObject[obj].get_data()

                                # 이미지 형식 확인
                                if xObject[obj]['/ColorSpace'] == '/DeviceRGB':
                                    mode = "RGB"
                                else:
                                    mode = "P"

                                # PIL 이미지로 변환
                                img = Image.frombytes(mode, size, data)

                                # 임시 파일로 저장
                                img_buffer = io.BytesIO()
                                img.save(img_buffer, format='PNG')
                                img_buffer.seek(0)

                                extracted_images.append({
                                    'page': page_num + 1,
                                    'data': img_buffer.getvalue(),
                                    'size': size
                                })
                                extracted_content['images'] += 1

                            except:
                                pass
            except:
                pass

        extracted_content['text'] = '\n'.join(all_text)

        # 새 PDF 생성
        os.makedirs(output_dir, exist_ok=True)
        clean_file = os.path.join(output_dir, f"{file_name}_reconstructed.pdf")

        # SimpleDocTemplate을 사용하여 PDF 생성
        doc = SimpleDocTemplate(
            clean_file,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )

        # 스타일 설정
        styles = getSampleStyleSheet()
        normal_style = styles['Normal']
        heading_style = styles['Heading1']

        # PDF 내용 구성
        story = []

        # 제목 추가
        title = Paragraph(f"Reconstructed Document: {file_name}", heading_style)
        story.append(title)
        story.append(Spacer(1, 12))

        # 정보 추가
        info_text = f"Original pages: {num_pages}<br/>Extracted images: {extracted_content['images']}<br/>This is a reconstructed document with potentially harmful elements removed."
        info = Paragraph(info_text, normal_style)
        story.append(info)
        story.append(Spacer(1, 24))

        # 텍스트 내용 추가
        if all_text:
            for text_block in all_text:
                if text_block.startswith("--- Page"):
                    # 페이지 구분자
                    page_style = ParagraphStyle(
                        'PageMarker',
                        parent=normal_style,
                        textColor='blue',
                        alignment=TA_CENTER,
                        fontSize=12,
                        spaceAfter=12
                    )
                    para = Paragraph(text_block, page_style)
                else:
                    # 일반 텍스트
                    # 긴 텍스트를 단락으로 분리
                    if text_block:
                        lines = text_block.split('\n')
                        for line in lines:
                            if line.strip():
                                # HTML 특수문자 이스케이프
                                safe_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                                para = Paragraph(safe_line, normal_style)
                                story.append(para)

                if text_block.startswith("--- Page") and text_block != all_text[-1]:
                    story.append(PageBreak())

        # 이미지 추가 (안전하게)
        if extracted_images and extracted_content['images'] <= 10:  # 최대 10개 이미지만
            story.append(PageBreak())
            story.append(Paragraph("Extracted Images", heading_style))
            story.append(Spacer(1, 12))

            for idx, img_info in enumerate(extracted_images[:10]):
                try:
                    # 이미지를 임시 파일로 저장
                    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_file:
                        tmp_file.write(img_info['data'])
                        tmp_path = tmp_file.name

                    # ReportLab 이미지 객체 생성
                    img = RLImage(tmp_path)

                    # 이미지 크기 조정 (페이지에 맞게)
                    max_width = 6 * inch
                    max_height = 8 * inch

                    # 원본 비율 유지하며 크기 조정
                    width, height = img_info['size']
                    aspect = height / float(width)

                    if width > max_width:
                        width = max_width
                        height = width * aspect

                    if height > max_height:
                        height = max_height
                        width = height / aspect

                    img.drawWidth = width
                    img.drawHeight = height

                    # 이미지 캡션
                    caption = Paragraph(f"Image from page {img_info['page']}", normal_style)
                    story.append(caption)
                    story.append(img)
                    story.append(Spacer(1, 12))

                    # 임시 파일 삭제
                    os.unlink(tmp_path)

                except:
                    pass

        # PDF 생성
        try:
            doc.build(story)
        except Exception as e:
            # 오류 발생 시 기본 PDF 생성
            print(f"PDF 생성 오류: {e}, 기본 PDF 생성")
            create_basic_pdf(clean_file, file_name, extracted_content)

        return clean_file, extracted_content

    except Exception as e:
        print(f"PDF 재조립 오류: {e}")
        return None, None


def create_basic_pdf(file_path: str, original_name: str, content_info: dict):
    """기본 PDF 생성 (오류 발생 시 대체)"""
    try:
        c = canvas.Canvas(file_path, pagesize=letter)
        width, height = letter

        # 제목
        c.setFont("Helvetica-Bold", 16)
        c.drawString(72, height - 72, f"Reconstructed Document: {original_name}")

        # 정보
        c.setFont("Helvetica", 12)
        y_position = height - 120

        info_lines = [
            f"Original pages: {content_info.get('pages', 0)}",
            f"Extracted text length: {len(content_info.get('text', ''))} characters",
            f"Extracted images: {content_info.get('images', 0)}",
            "",
            "This is a reconstructed document with potentially harmful",
            "elements removed. The original formatting may have been",
            "altered for security purposes."
        ]

        for line in info_lines:
            c.drawString(72, y_position, line)
            y_position -= 20

        # 텍스트 샘플 (첫 1000자)
        if content_info.get('text'):
            y_position -= 40
            c.setFont("Helvetica-Bold", 14)
            c.drawString(72, y_position, "Text Content (Sample):")
            y_position -= 20

            c.setFont("Helvetica", 10)
            text_sample = content_info['text'][:1000]

            # 텍스트를 줄 단위로 나누기
            words = text_sample.split()
            lines = []
            current_line = []
            line_width = 0
            max_width = width - 144  # 좌우 여백 제외

            for word in words:
                word_width = c.stringWidth(word + " ", "Helvetica", 10)
                if line_width + word_width > max_width:
                    lines.append(' '.join(current_line))
                    current_line = [word]
                    line_width = word_width
                else:
                    current_line.append(word)
                    line_width += word_width

            if current_line:
                lines.append(' '.join(current_line))

            # 텍스트 그리기
            for line in lines[:30]:  # 최대 30줄
                if y_position < 72:
                    c.showPage()
                    y_position = height - 72

                c.drawString(72, y_position, line)
                y_position -= 14

        c.save()

    except Exception as e:
        print(f"기본 PDF 생성 오류: {e}")