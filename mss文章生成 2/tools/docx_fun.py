from datetime import datetime
import sys

from docxtpl import DocxTemplate
from PIL import Image


def find_paragraph_with_string(doc, search_string):
    """Return the index of the paragraph containing the target marker."""
    for index, paragraph in enumerate(doc.paragraphs):
        if search_string in paragraph.text:
            return index
    sys.exit(1)


def delete_paragraph_index(doc, target_string, line):
    """Delete the paragraph block that starts with the given template marker."""
    for index, paragraph in enumerate(doc.paragraphs):
        if target_string in paragraph.text:
            for _ in range(line):
                paragraph = doc.paragraphs[index]
                p_element = paragraph._element
                p_element.getparent().remove(p_element)


def convert_date(date_str):
    """Convert 2024.04.06 style dates into the format used by the template."""
    date_obj = datetime.strptime(date_str, "%Y.%m.%d")
    return date_obj.strftime("%Y年%m月%d日")


def split_vulner_name(vulner_name):
    """Collapse names that contain / so they can be used in output file names."""
    if "/" in vulner_name:
        split_name = vulner_name.split("/")
        vulner_name = split_name[0] + split_name[-1]
    return vulner_name


def change_docx(templates_path, docx_out_path, context):
    """Render a docx template with the provided context and save the output."""
    docx = DocxTemplate(templates_path)
    docx.render(context, autoescape=True)
    docx.save(docx_out_path)


def resize_image(input_image_path, size_multiplier):
    """Resize an image in-place while keeping the original aspect ratio."""
    original_image = Image.open(input_image_path)
    width, height = original_image.size
    new_width = int(width / size_multiplier)
    new_height = int(height / size_multiplier)
    resized_image = original_image.resize((new_width, new_height), Image.LANCZOS)
    resized_image.save(input_image_path)
