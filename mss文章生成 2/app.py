from datetime import datetime
from pathlib import Path
import re
import uuid

from docx import Document

from tools import docx_fun
from tools import tonggao

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
REGULATOR_TEMPLATE = BASE_DIR / "templates" / "模板-漏洞应急响应通告_监管.docx"

# 直接在这里填写模板生成所需参数。
INPUT_DATA = {
    "vulner_name": "测试组件远程代码执行漏洞(CVE-2026-9999)",
    "vulner_number_1": "CVE-2026-9999",
    "vulner_number_2": "",
    "new_vulner_name": "",
    "vulner_date": "",
    "vulner_time_line": "",
    "object_name": "测试组件",
    "object_desc": "这是一个用于验证模板生成链路的本地测试组件。",
    "vulner_version": "测试组件 1.0-2.0",
    "vulner_type": "远程代码执行",
    "user_auth": "无需认证",
    "pre_condition": "目标组件对外开放管理接口。",
    "trigger_mode": "构造恶意请求触发。",
    "utilize_difficulty": "低",
    "hazard_level": "攻击者可直接控制目标主机。",
    "vuln_level": "高危",
    "vulner_desc": "由于输入校验缺失，攻击者可在特定接口注入恶意命令并远程执行。",
    "official_solution": "升级至官方修复版本，或临时关闭高风险接口。",
    "reference_link": "https://example.com/advisory",
    "reference_link1": "",
    "reference_link2": "",
}

FIELD_DEFINITIONS = [
    {"name": "vulner_name", "label": "漏洞名称", "required": True},
    {"name": "vulner_number_1", "label": "漏洞编号", "required": False},
    {"name": "vulner_number_2", "label": "正文漏洞编号描述", "required": False},
    {"name": "new_vulner_name", "label": "封面标题", "required": False},
    {"name": "vulner_date", "label": "发布日期", "required": False},
    {"name": "vulner_time_line", "label": "时间轴日期", "required": False},
    {"name": "object_name", "label": "组件名称", "required": True},
    {"name": "object_desc", "label": "组件简介", "required": True},
    {"name": "vulner_version", "label": "影响范围", "required": True},
    {"name": "vulner_type", "label": "漏洞类型", "required": True},
    {"name": "user_auth", "label": "权限要求", "required": True},
    {"name": "pre_condition", "label": "利用前提", "required": True},
    {"name": "trigger_mode", "label": "触发方式", "required": True},
    {"name": "utilize_difficulty", "label": "利用难度", "required": True},
    {"name": "hazard_level", "label": "危害程度", "required": True},
    {"name": "vuln_level", "label": "漏洞评级", "required": True},
    {"name": "vulner_desc", "label": "漏洞描述", "required": True},
    {"name": "official_solution", "label": "官方修复建议", "required": True},
    {"name": "reference_link", "label": "参考链接1", "required": False},
    {"name": "reference_link1", "label": "参考链接2", "required": False},
    {"name": "reference_link2", "label": "参考链接3", "required": False},
]


def ensure_runtime_dirs():
    """Ensure the output directory exists before writing files."""
    OUTPUT_DIR.mkdir(exist_ok=True)


def current_time_strings():
    """Return the default date strings used by the templates."""
    now_time = datetime.now()
    formatted_time = now_time.strftime("%Y-%m-%d")
    vulner_date = now_time.strftime("%Y年%m月%d日").replace("年0", "年").replace("月0", "月")
    vulner_time_line = now_time.strftime("%Y/%m/%d")
    return formatted_time, vulner_date, vulner_time_line


def normalize_text(payload, field_name, default=""):
    """Read a text field from the input dictionary and strip surrounding spaces."""
    value = payload.get(field_name, default)
    if value is None:
        return default
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()


def derive_short_name(vulner_name):
    """Build the cover title when it is not provided explicitly."""
    short_name = re.sub(r"[\(（][^\)）]*[\)）]", "", vulner_name).strip()
    return short_name or vulner_name


def build_context(payload):
    """Convert the input dictionary into the exact template context required by docxtpl."""
    formatted_time, default_vulner_date, default_time_line = current_time_strings()
    required_fields = [field["name"] for field in FIELD_DEFINITIONS if field["required"]]
    missing_fields = [field for field in required_fields if not normalize_text(payload, field)]
    if missing_fields:
        raise ValueError(f"缺少必填字段: {', '.join(missing_fields)}")

    vulner_name = normalize_text(payload, "vulner_name")
    vulner_number_1 = normalize_text(payload, "vulner_number_1")
    vulner_number_2 = normalize_text(
        payload,
        "vulner_number_2",
        f"漏洞编号：{vulner_number_1}，" if vulner_number_1 else "",
    )

    context = {
        "vulner_name": vulner_name,
        "new_vulner_name": normalize_text(payload, "new_vulner_name") or derive_short_name(vulner_name),
        "vulner_number_1": vulner_number_1,
        "vulner_number_2": vulner_number_2,
        "vulner_date": normalize_text(payload, "vulner_date") or default_vulner_date,
        "vulner_time_line": normalize_text(payload, "vulner_time_line") or default_time_line,
        "object_name": normalize_text(payload, "object_name"),
        "object_desc": normalize_text(payload, "object_desc"),
        "vulner_version": normalize_text(payload, "vulner_version"),
        "vulner_type": normalize_text(payload, "vulner_type"),
        "user_auth": normalize_text(payload, "user_auth"),
        "pre_condition": normalize_text(payload, "pre_condition"),
        "trigger_mode": normalize_text(payload, "trigger_mode"),
        "utilize_difficulty": normalize_text(payload, "utilize_difficulty"),
        "hazard_level": normalize_text(payload, "hazard_level"),
        "vuln_level": normalize_text(payload, "vuln_level"),
        "vulner_desc": normalize_text(payload, "vulner_desc"),
        "official_solution": normalize_text(payload, "official_solution"),
        "reference_link": normalize_text(payload, "reference_link"),
        "reference_link1": normalize_text(payload, "reference_link1"),
        "reference_link2": normalize_text(payload, "reference_link2"),
    }
    return formatted_time, context


def sanitize_output_name(vulner_name):
    """Normalize the vulnerability name before using it as a folder or file name."""
    safe_name = docx_fun.split_vulner_name(vulner_name)
    safe_name = re.sub(r'[\\/:*?"<>|]+', "_", safe_name).strip()
    return safe_name or "漏洞通告"


def build_output_paths(formatted_time, vulner_name):
    """Create the dated output folder and return both generated file paths."""
    safe_name = sanitize_output_name(vulner_name)
    output_path = OUTPUT_DIR / formatted_time / safe_name
    output_path.mkdir(parents=True, exist_ok=True)
    tonggao_file = output_path / f"{safe_name}应急响应通告.docx"
    jianguan_file = output_path / f"{safe_name}应急响应通告_监管.docx"
    return tonggao_file, jianguan_file


def render_with_context(document, output_path, context):
    """Save an intermediate docx and render template placeholders into the final file."""
    temp_path = OUTPUT_DIR / f".tmp_{uuid.uuid4().hex}.docx"
    document.save(temp_path)
    try:
        docx_fun.change_docx(str(temp_path), str(output_path), context)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def generate_notice(payload):
    """Generate both notice documents from the input dictionary."""
    ensure_runtime_dirs()
    formatted_time, context = build_context(payload)

    tonggao_context, notice_document = tonggao.solution(
        image_filename="",
        uploadCheck="false",
        get_version="",
    )
    merged_context = context | tonggao_context
    tonggao_file, jianguan_file = build_output_paths(formatted_time, context["vulner_name"])

    render_with_context(notice_document, tonggao_file, merged_context)
    render_with_context(Document(str(REGULATOR_TEMPLATE)), jianguan_file, merged_context)

    return {
        "notice": str(tonggao_file),
        "regulator_notice": str(jianguan_file),
    }


def main():
    """Run the local document generation flow using the parameters defined in INPUT_DATA."""
    files = generate_notice(INPUT_DATA)
    print("文档生成成功")
    print(f"普通通告: {files['notice']}")
    print(f"监管通告: {files['regulator_notice']}")


if __name__ == "__main__":
    main()
