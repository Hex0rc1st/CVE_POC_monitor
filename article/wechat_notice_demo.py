#!/usr/bin/env python3
"""Generate MSS notice documents from a WeChat article or markdown source."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Any

import requests
from bs4 import BeautifulSoup
from openai import OpenAI

import app

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
DEFAULT_MODEL = os.environ.get("llm_model", "deepseek-r1")
HTTP_TIMEOUT = 20
MAX_REFERENCE_TEXT = 4000
MAX_BODY_TEXT = 12000
ALLOWED_PUBLISHERS = ("360漏洞研究院", "奇安信 CERT")
PUBLISHER_ALIASES = {
    "360漏洞研究院": ("360漏洞研究院", "原创360漏洞研究院", "360 漏洞研究院"),
    "奇安信 CERT": ("奇安信 CERT", "奇安信CERT", "原创奇安信 CERT", "QAX CERT"),
}
FORBIDDEN_SOURCE_TERMS = ("360", "奇安信", "QAX", "qax")
FORBIDDEN_REFERENCE_PATTERNS = (
    "mp.weixin.qq.com",
    ".360.net",
    "loudongyun.360.net",
    "qianxin.com",
    "奇安信",
    "360",
)

FACTS_PROMPT = """你是漏洞情报抽取智能体。
你的任务是根据公众号漏洞通告 markdown 和参考链接文本，抽取结构化事实。
要求：
1. 只抽取事实，不写营销文案。
2. 优先采用参考链接中的官方事实，其次使用公众号正文。
3. 不要保留来源品牌宣传性表述。
4. 输出严格 JSON，不要代码块，不要解释。
5. 字段缺失时填空字符串。
6. 受影响版本必须区分“受影响范围”和“修复版本/修复下载链接”，不能把修复版本误写成影响范围。
7. affected_versions 输出格式必须为：`版本 (≤|<) 组件名 (≤|<) 版本`；如果有多个范围，用换行分隔。

输出字段：
{
  "vulner_name": "",
  "aliases": [],
  "publish_date": "YYYY-MM-DD",
  "object_name": "",
  "object_desc_facts": "",
  "affected_versions": "",
  "fixed_versions": "",
  "download_links": [],
  "vulner_version": "",
  "vulner_type": "",
  "user_auth": "",
  "pre_condition": "",
  "trigger_scope": "",
  "trigger_mode": "",
  "utilize_difficulty": "",
  "hazard_level_facts": "",
  "vuln_level": "",
  "vulner_desc_facts": "",
  "official_solution_facts": "",
  "reference_links": [],
  "reference_summary": ""
}
"""

PAYLOAD_PROMPT = """你是漏洞通告编写智能体。
你的任务是根据已抽取的结构化事实，生成可直接用于 MSS Word 模板的 JSON。
要求：
1. 绝不能出现 360、奇安信、QAX 以及任何来源公众号品牌字样。
2. object_desc、vulner_desc、official_solution 必须重写总结，不能照抄原文句子。
3. 语气保持中立、客观、监管通告风格。
4. 如果原始事实不足，允许做保守补全，但不要编造具体版本号、时间和链接。
5. 输出严格 JSON，不要代码块，不要解释。
6. user_auth 只能填写“需要用户认证”或“不需要用户认证”。
7. pre_condition 只填写是否有前置配置要求；如果没有，写“默认配置”。
8. trigger_mode 只填写“远程”或“本地”。
9. object_desc 是组件本身的简短介绍，不能写成漏洞影响说明。
10. vulner_version 必须写受影响范围，不能写修复版本。
11. official_solution 必须包含修复版本或升级建议，并明确给出下载链接；如果参考资料里有 GitHub releases 链接，优先使用该链接。
12. vulner_version 输出格式必须为：`版本 (≤|<) 组件名 (≤|<) 版本`；如果有多个范围，用换行分隔。

输出字段：
{
  "vulner_name": "",
  "vulner_number_1": "",
  "vulner_number_2": "",
  "new_vulner_name": "",
  "vulner_date": "",
  "vulner_time_line": "",
  "object_name": "",
  "object_desc": "",
  "vulner_version": "",
  "vulner_type": "",
  "user_auth": "",
  "pre_condition": "",
  "trigger_mode": "",
  "utilize_difficulty": "",
  "hazard_level": "",
  "vuln_level": "",
  "vulner_desc": "",
  "official_solution": "",
  "reference_link": "",
  "reference_link1": "",
  "reference_link2": ""
}
"""

REPAIR_PROMPT = """你是漏洞通告修复智能体。
你的任务是修复当前 JSON 中的问题并重新输出完整 JSON。
要求：
1. 绝不能出现 360、奇安信、QAX 及其变体。
2. 对被指出疑似照抄的长文本字段，必须重新概括改写。
3. 保留已有正确事实，不要丢字段。
4. 输出严格 JSON，不要代码块，不要解释。
5. user_auth 只能为“需要用户认证”或“不需要用户认证”；pre_condition 若无特殊要求必须写“默认配置”；trigger_mode 只能为“远程”或“本地”。
6. vulner_version 必须采用 `版本 (≤|<) 组件名 (≤|<) 版本` 格式，多段范围用换行分隔。
"""

VULNER_DESC_PROMPT = """你是漏洞技术描述重写智能体。
你的任务是基于公众号漏洞描述段和参考资料正文，生成一段适合正式通告的“漏洞描述”。
要求：
1. 只写漏洞本身的技术描述，不写修复建议、营销语或来源介绍。
2. 必须优先吸收输入中的技术细节，例如触发端点、可控参数、危险函数、内存/解析/权限边界缺陷、利用链等。
3. 不能照抄原文句子，要压缩、重写、优化表达。
4. 绝不能出现 360、奇安信、QAX 及其变体。
5. 输出 2-4 句中文，面向漏洞通告风格。
6. 如果输入事实不足，再做保守描述，但不要编造不存在的技术细节。
7. 只输出最终文本，不要 JSON，不要解释。
"""

OBJECT_DESC_PROMPT = """你是组件介绍生成智能体。
你的任务是根据公众号正文、参考资料和组件名称，生成一段简短的“组件介绍”。
要求：
1. 这是对组件本身的介绍，不是漏洞介绍，不写漏洞影响、修复建议、营销文案。
2. 优先依据输入中的客观事实，说明组件的定位、主要用途或典型场景。
3. 绝不能出现 360、奇安信、QAX 及其变体。
4. 输出 2-3 句中文，简洁、正式。
5. 如果事实有限，可以做保守概括，但不要写“用于提供相关功能的软件组件”这类空话。
6. 只输出最终文本，不要 JSON，不要解释。
"""

VULNER_NAME_PROMPT = """你是漏洞名称优化智能体。
你的任务是基于原始漏洞标题、表格中的漏洞名称、漏洞类型和组件名称，生成适合正式通告的漏洞名称。
要求：
1. 输出格式优先为：XXX（组件）xxx（模块、接口、路由或子功能，可选）XXX（攻击类型）漏洞。
2. 不要保留“已复现”“在野漏洞预警”“安全风险通告”“可导致”等宣传或结论性措辞。
3. 绝不能出现 360、奇安信、QAX 及其变体。
4. 只输出最终漏洞名称，不要解释，不要 JSON。
5. 如果无法判断模块、接口或路由，可以省略该部分，但整体名称仍需简洁、正式。
"""


def parse_args() -> argparse.Namespace:
    """Parse the command line arguments for the demo script."""
    parser = argparse.ArgumentParser(description="根据微信公众号文章生成两篇 MSS 通告")
    parser.add_argument("source", help="公众号文章链接、Markdown 文件路径，或远程 Markdown 链接")
    parser.add_argument(
        "--keep-md",
        action="store_true",
        help="保留抓取到的 Markdown 中间文件目录",
    )
    parser.add_argument(
        "--debug-json",
        action="store_true",
        help="在输出目录中额外写出中间抽取结果 JSON",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="以单行 JSON 输出结果，便于外部脚本解析",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="将执行阶段打印到 stderr，便于定位卡住的位置",
    )
    return parser.parse_args()


def is_url(value: str) -> bool:
    """Return whether the provided string looks like an HTTP URL."""
    return value.startswith("http://") or value.startswith("https://")


def sanitize_whitespace(text: str) -> str:
    """Normalize whitespace so later parsing and validation are stable."""
    return re.sub(r"\s+", " ", text or "").strip()


def stage_log(enabled: bool, message: str) -> None:
    """Print one progress line to stderr without affecting JSON stdout."""
    if not enabled:
        return
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", file=sys.stderr, flush=True)


def format_elapsed_seconds(start_time: float) -> str:
    """Format elapsed wall time as a short string for verbose logs."""
    return f"{(perf_counter() - start_time):.2f}s"


def strip_trailing_sentence_punct(text: str) -> str:
    """Remove trailing sentence punctuation when the template already appends it."""
    return re.sub(r"[。．.!！；;]+$", "", sanitize_whitespace(text))


def normalize_compare_text(text: str) -> str:
    """Normalize text for copy-detection comparisons."""
    return re.sub(r"\s+", "", text or "").lower()


def remove_source_mentions(text: str) -> str:
    """Remove publisher branding terms from generated or extracted text."""
    cleaned = text or ""
    cleaned = re.sub(r"原创\s*360漏洞研究院", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"360漏洞研究院", "安全研究团队", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"奇安信\s*CERT", "安全团队", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"奇安信", "安全团队", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bQAX\b", "安全团队", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\b360\b", "相关安全团队", cleaned, flags=re.IGNORECASE)
    return sanitize_whitespace(cleaned)


def normalize_publisher_text(text: str) -> str:
    """Normalize publisher text so alias matching is resilient to spacing variants."""
    cleaned = text.replace("\u00a0", " ").replace("\u200b", "").replace("\ufeff", "")
    cleaned = re.sub(r"\s+", "", cleaned)
    return cleaned.lower()


def strip_large_base64_lines(text: str) -> str:
    """Drop large base64 image lines to keep prompts small and clean."""
    cleaned_lines = []
    for line in text.splitlines():
        if "base64," in line and len(line) > 300:
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def convert_date_formats(date_str: str) -> tuple[str, str]:
    """Convert YYYY-MM-DD date strings into the two template date formats."""
    date_obj = datetime.strptime(date_str, "%Y-%m-%d")
    vulner_date = date_obj.strftime("%Y年%m月%d日").replace("年0", "年").replace("月0", "月")
    vulner_time_line = date_obj.strftime("%Y/%m/%d")
    return vulner_date, vulner_time_line


def get_wechat_tool_path() -> Path:
    """Choose the platform-specific wechatmp2markdown binary for the current runtime."""
    system_name = platform.system().lower()
    if "darwin" in system_name:
        candidate = BASE_DIR / "wechatmp2markdown-v1.1.11_osx_amd64"
    else:
        candidate = BASE_DIR / "wechatmp2markdown-v1.1.11_linux_amd64"
    if not candidate.exists():
        raise FileNotFoundError(f"缺少转换工具: {candidate}")
    candidate.chmod(candidate.stat().st_mode | 0o111)
    return candidate


def run_wechat_to_markdown(article_url: str) -> Path:
    """Run the local wechatmp2markdown binary and return the generated markdown path."""
    wechat_tool = get_wechat_tool_path()
    run_dir = UPLOAD_DIR / f"demo_{int(datetime.now().timestamp())}"
    run_dir.mkdir(parents=True, exist_ok=True)
    command = [str(wechat_tool), article_url, str(run_dir)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            "wechatmp2markdown 执行失败:\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    markdown_files = sorted(run_dir.rglob("*.md"))
    if not markdown_files:
        raise FileNotFoundError(f"未在 {run_dir} 中找到 markdown 输出")
    return markdown_files[0]


def resolve_markdown_source(source: str) -> tuple[Path, str]:
    """Resolve a source into a local markdown path and the original article URL when available."""
    path = Path(source)
    if path.exists() and path.is_file():
        return path, ""
    if not is_url(source):
        raise FileNotFoundError(f"找不到输入文件: {source}")
    if "mp.weixin.qq.com" in source:
        return run_wechat_to_markdown(source), source

    response = requests.get(source, timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    temp_dir = UPLOAD_DIR / f"remote_md_{int(datetime.now().timestamp())}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_file = temp_dir / "remote.md"
    temp_file.write_text(response.text, encoding="utf-8")
    return temp_file, source


def load_markdown(markdown_path: Path) -> str:
    """Load markdown content from disk and remove large noise blocks."""
    return strip_large_base64_lines(markdown_path.read_text(encoding="utf-8"))


def detect_publisher(markdown_text: str) -> str:
    """Detect and validate the source publisher from the markdown header."""
    head_lines = [line.strip() for line in markdown_text.splitlines()[:12] if line.strip()]
    head_text = "\n".join(head_lines)
    normalized_head = normalize_publisher_text(head_text)
    for publisher in ALLOWED_PUBLISHERS:
        aliases = PUBLISHER_ALIASES.get(publisher, (publisher,))
        for alias in aliases:
            if normalize_publisher_text(alias) in normalized_head:
                return publisher
    raise ValueError("仅支持 360漏洞研究院 和 奇安信 CERT 的文章")


def extract_title(markdown_text: str) -> str:
    """Extract the main article title from the first markdown heading."""
    match = re.search(r"^#\s+(.*)$", markdown_text, flags=re.MULTILINE)
    if not match:
        raise ValueError("未能从 markdown 中提取文章标题")
    return sanitize_whitespace(match.group(1))


def extract_article_date(markdown_text: str) -> str:
    """Extract the article date from the header area."""
    match = re.search(r"(20\d{2}-\d{2}-\d{2})", markdown_text[:500])
    if match:
        return match.group(1)
    return datetime.now().strftime("%Y-%m-%d")


def extract_table_html(markdown_text: str) -> str:
    """Return the first HTML table block from the markdown content."""
    match = re.search(r"(<table.*?</table>)", markdown_text, flags=re.IGNORECASE | re.DOTALL)
    return match.group(1) if match else ""


def extract_table_fields(markdown_text: str) -> dict[str, str]:
    """Parse the first HTML table into a flat key-value mapping."""
    table_html = extract_table_html(markdown_text)
    if not table_html:
        return {}

    soup = BeautifulSoup(table_html, "html.parser")
    fields: dict[str, str] = {}
    for row in soup.find_all("tr"):
        cells = [sanitize_whitespace(cell.get_text(" ", strip=True)) for cell in row.find_all(["td", "th"])]
        cells = [cell for cell in cells if cell]
        if len(cells) == 2:
            fields[cells[0]] = cells[1]
        elif len(cells) == 4:
            fields[cells[0]] = cells[1]
            fields[cells[2]] = cells[3]
    return fields


def remove_html_blocks(markdown_text: str) -> str:
    """Remove HTML blocks so plain-text section extraction is easier."""
    text = re.sub(r"<table.*?</table>", "\n", markdown_text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"!\[\]\[[^\]]+\]", " ", text)
    text = re.sub(r"\[[0-9]+\]:\s*data:image[^\n]+", " ", text)
    return text


def extract_reference_links(markdown_text: str) -> list[str]:
    """Extract candidate vulnerability reference links from the markdown."""
    reference_section = ""
    section_match = re.search(
        r"^\s*(?:\*\*+\s*)?(?:参考资料|参考链接|参考信息)\s*(?:\*\*+)?\s*$"
        r"(.*?)(?:^\s*(?:\*\*+\s*)?\d+(?:\s*\*\*+)?\s*$|^\s*(?:时间线|更多漏洞情报)\s*$|\Z)",
        markdown_text,
        flags=re.IGNORECASE | re.DOTALL | re.MULTILINE,
    )
    if section_match:
        reference_section = section_match.group(1)

    source_text = reference_section or markdown_text
    raw_links = re.findall(r"https?://[^\s<>\]）)]+", source_text)
    if not raw_links and reference_section:
        raw_links = re.findall(r"https?://[^\s<>\]）)]+", markdown_text)
    cleaned_links: list[str] = []
    for link in raw_links:
        cleaned = link.rstrip(").,]）")
        lowered = cleaned.lower()
        if any(pattern.lower() in lowered for pattern in FORBIDDEN_REFERENCE_PATTERNS):
            continue
        if cleaned not in cleaned_links:
            cleaned_links.append(cleaned)
    return cleaned_links[:6]


def extract_plain_sections(markdown_text: str) -> dict[str, str]:
    """Extract the plain-text body and key sections for later summarization."""
    plain_text = remove_html_blocks(markdown_text)
    lines = [line.strip() for line in plain_text.splitlines()]
    raw_text_without_tables = re.sub(r"<table.*?</table>", "\n", markdown_text, flags=re.IGNORECASE | re.DOTALL)
    raw_lines = [line.strip() for line in raw_text_without_tables.splitlines()]
    body_lines = [
        line for line in lines
        if line
        and not line.startswith("#")
        and "点击↑蓝字关注" not in line
        and "公众号粉丝交流群" not in line
        and "原创 " not in line
    ]
    joined = "\n".join(body_lines)
    security_update = ""

    # The markdown exported from wechatmp2markdown has stable subsection headings,
    # so extract them explicitly before falling back to broad regex matching.
    def normalize_section_heading(text: str) -> str:
        """Normalize markdown subsection headings so matching ignores decoration."""
        cleaned = re.sub(r"[*#>\s:：\-\u00a0]+", "", text or "")
        return cleaned

    def clean_markdown_line(text: str) -> str:
        """Clean markdown artifacts while preserving version operators and URLs."""
        cleaned = re.sub(r"!\[[^\]]*\]\[[^\]]*\]", " ", text)
        cleaned = re.sub(r"^\[[0-9]+\]:\s*.*$", " ", cleaned)
        cleaned = cleaned.replace("**", " ").replace("__", " ")
        return remove_source_mentions(sanitize_whitespace(cleaned))

    def extract_markdown_section(title: str, preserve_lines: bool = False) -> str:
        """Extract a named markdown subsection body from the cleaned article text."""
        known_titles = {
            "漏洞详情",
            "漏洞影响范围",
            "影响组件",
            "漏洞描述",
            "影响范围",
            "影响版本",
            "其他受影响组件",
            "复现情况",
            "受影响资产情况",
            "处置建议",
            "安全更新",
            "修复建议",
            "官方修复建议",
            "参考资料",
            "参考链接",
            "时间线",
            "漏洞情报服务",
        }
        target = normalize_section_heading(title)
        collecting = False
        collected: list[str] = []
        for line in raw_lines:
            normalized_line = normalize_section_heading(line)
            if not normalized_line:
                continue
            if normalized_line == target:
                collecting = True
                continue
            if collecting and normalized_line in known_titles:
                break
            if collecting and normalized_line not in {"0", "01", "02", "03", "04", "05", "06", "07", "08"}:
                cleaned_line = clean_markdown_line(line)
                if cleaned_line:
                    collected.append(cleaned_line)
        if preserve_lines:
            return "\n".join(collected)
        return sanitize_whitespace(" ".join(collected))

    component_text = extract_markdown_section("影响组件")
    vulnerability_text = extract_markdown_section("漏洞描述")
    affected_versions_text = extract_markdown_section("影响版本")
    if not affected_versions_text:
        affected_range_text = extract_markdown_section("漏洞影响范围", preserve_lines=True)
        if affected_range_text:
            range_lines = [sanitize_whitespace(line) for line in affected_range_text.splitlines() if sanitize_whitespace(line)]
            label_patterns = (
                "受影响的软件版本",
                "受影响版本",
                "影响版本",
                "affected software versions",
                "affected versions",
            )
            collected_version_lines: list[str] = []
            for index, line in enumerate(range_lines):
                lowered = line.lower()
                if not any(label in lowered for label in label_patterns):
                    continue
                inline_value = re.sub(
                    r"^(?:受影响的软件版本|受影响版本|影响版本|affected software versions|affected versions)[:：]?\s*",
                    "",
                    line,
                    flags=re.IGNORECASE,
                )
                if inline_value:
                    collected_version_lines.append(sanitize_whitespace(inline_value))
                for next_line in range_lines[index + 1:]:
                    if re.search(r"(?:修复建议|安全更新|参考资料|参考链接|时间线|处置建议)", next_line, flags=re.IGNORECASE):
                        break
                    collected_version_lines.append(next_line)
                break
            if collected_version_lines:
                affected_versions_text = "\n".join(dict.fromkeys(collected_version_lines))
            else:
                affected_versions_text = sanitize_whitespace(affected_range_text)
    security_update = (
        extract_markdown_section("安全更新")
        or extract_markdown_section("修复建议")
        or extract_markdown_section("官方修复建议")
    )
    if not security_update:
        update_match = re.search(
            r"(?:安全更新|修复建议|官方修复建议)(.*?)(?:\n\s*\*\*\d+\*\*|\n\s*参考资料|\n\s*时间线|\Z)",
            joined,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if update_match:
            security_update = sanitize_whitespace(update_match.group(1))

    intro_lines = []
    for line in body_lines:
        if "参考资料" in line or "参考链接" in line:
            break
        if line.startswith("**0"):
            continue
        intro_lines.append(line)
    intro_text = sanitize_whitespace(" ".join(intro_lines))
    return {
        "intro_text": remove_source_mentions(intro_text)[:MAX_BODY_TEXT],
        "security_update": remove_source_mentions(security_update)[:2000],
        "component_text": component_text[:2000],
        "vulnerability_text": vulnerability_text[:3000],
        "affected_versions_text": affected_versions_text[:1000],
        "plain_text": remove_source_mentions(sanitize_whitespace(joined))[:MAX_BODY_TEXT],
    }


def fetch_reference_text(url: str) -> str:
    """Fetch and simplify reference page content so it can be used as grounding material."""
    try:
        response = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        response.raise_for_status()
    except requests.RequestException as exc:
        return f"[抓取失败] {url}: {exc}"

    content_type = response.headers.get("content-type", "")
    if "text/plain" in content_type:
        text = response.text
    else:
        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text("\n", strip=True)
    return sanitize_whitespace(text)[:MAX_REFERENCE_TEXT]


def collect_reference_materials(reference_links: list[str]) -> list[dict[str, str]]:
    """Fetch all candidate reference links and keep the cleaned page snippets."""
    materials = []
    for link in reference_links:
        materials.append({"url": link, "content": fetch_reference_text(link)})
    return materials


def extract_identifiers(title: str, fields: dict[str, str]) -> list[str]:
    """Extract CVE/QVD/CNVD style identifiers from title and table fields."""
    text = " ".join([title] + list(fields.values()))
    pattern = r"\b(?:CVE|QVD|CNVD|CNNVD)-\d{4}-\d+\b"
    identifiers = re.findall(pattern, text, flags=re.IGNORECASE)
    unique_identifiers = []
    for item in identifiers:
        normalized = item.upper()
        if normalized not in unique_identifiers:
            unique_identifiers.append(normalized)
    cve_items = [item for item in unique_identifiers if item.startswith("CVE-")]
    other_items = [item for item in unique_identifiers if not item.startswith("CVE-")]
    return cve_items + other_items


def build_reference_text(reference_materials: list[dict[str, str]]) -> str:
    """Join reference contents into a single normalized block for rule extraction."""
    return "\n\n".join(item.get("content", "") for item in reference_materials)


def normalize_version_token(version: str) -> str:
    """Normalize version tokens before range formatting."""
    cleaned = sanitize_whitespace(version).strip(" ,;")
    cleaned = cleaned.replace("（", "(").replace("）", ")").replace("\u00a0", " ")
    if re.fullmatch(r"[0-9A-Za-z._/-]+\.", cleaned):
        cleaned = cleaned[:-1]
    return cleaned


def build_version_range_line(lower: str, lower_op: str, object_name: str, upper_op: str, upper: str) -> str:
    """Build a single affected-version line in the required normalized format."""
    lower_text = normalize_version_token(lower)
    upper_text = normalize_version_token(upper)
    if not lower_text or not upper_text:
        return ""
    return f"{lower_text} {lower_op} {object_name} {upper_op} {upper_text}"


def format_affected_versions(raw_text: str, object_name: str) -> str:
    """Normalize raw affected-version text into the required multi-line range format."""
    text = sanitize_whitespace(raw_text)
    if not text or "请参考官方通告" in text:
        return "请参考官方通告确认受影响范围。"
    raw_lines = [sanitize_whitespace(line) for line in (raw_text or "").splitlines() if sanitize_whitespace(line)]
    normalized_compare_text = "\n".join(
        line.replace("<=", "≤").replace(">=", "≥") for line in raw_lines
    ) or text.replace("<=", "≤").replace(">=", "≥")

    vendor_prefixed_lines = []
    for line in normalized_compare_text.splitlines():
        for vendor_prefixed_match in re.finditer(
            rf"([^\n]*?{re.escape(object_name)}[^\n]*?)\s*(≤|<|≥|>)\s*([0-9A-Za-z._/-]+)",
            line,
            flags=re.IGNORECASE,
        ):
            component_text = sanitize_whitespace(vendor_prefixed_match.group(1)).replace("（", "(").replace("）", ")")
            operator = vendor_prefixed_match.group(2)
            version = normalize_version_token(vendor_prefixed_match.group(3))
            rendered = f"{component_text} {operator} {version}"
            if rendered not in vendor_prefixed_lines:
                vendor_prefixed_lines.append(rendered)
    if vendor_prefixed_lines:
        return "\n".join(dict.fromkeys(vendor_prefixed_lines))

    direct_lines = []
    for line in normalized_compare_text.splitlines():
        normalized_line = sanitize_whitespace(line)
        if re.fullmatch(
            rf"[0-9A-Za-z._/-]+\s*(?:≤|<)\s*{re.escape(object_name)}\s*(?:≤|<)\s*[0-9A-Za-z._/-]+",
            normalized_line,
        ):
            direct_lines.append(normalized_line)
    if direct_lines:
        return "\n".join(dict.fromkeys(direct_lines))

    one_sided_patterns = [
        rf"{re.escape(object_name)}\s*(?:≤|<)\s*[0-9A-Za-z._/-]+",
        rf"{re.escape(object_name)}\s*(?:≥|>)\s*[0-9A-Za-z._/-]+",
    ]
    for pattern in one_sided_patterns:
        match = re.search(pattern, normalized_compare_text, flags=re.IGNORECASE)
        if match:
            return sanitize_whitespace(match.group(0))

    lines: list[str] = []

    introduced_match = re.search(
        rf"introduced with\s+{re.escape(object_name)}\s*v?([0-9A-Za-z._-]+).*?earlier versions are not affected",
        text,
        flags=re.IGNORECASE,
    )
    upper_bound_match = (
        re.search(
        rf"{re.escape(object_name)}\s+before\s+([0-9A-Za-z._/-]+)",
            text,
            flags=re.IGNORECASE,
        )
        or re.search(
            rf"{re.escape(object_name)}\s*<\s*([0-9A-Za-z._/-]+)",
            text,
            flags=re.IGNORECASE,
        )
        or re.search(
            rf"{re.escape(object_name)}\s*<=\s*([0-9A-Za-z._/-]+)",
            text,
            flags=re.IGNORECASE,
        )
    )
    if introduced_match and upper_bound_match:
        return build_version_range_line(
            lower=introduced_match.group(1),
            lower_op="≤",
            object_name=object_name,
            upper_op="<",
            upper=upper_bound_match.group(1),
        )

    between_patterns = [
        rf"{re.escape(object_name)}\s*>\s*([0-9A-Za-z._/-]+)\s*&&\s*{re.escape(object_name)}\s*<\s*([0-9A-Za-z._/-]+)",
        rf"{re.escape(object_name)}\s*>=\s*([0-9A-Za-z._/-]+)\s*&&\s*{re.escape(object_name)}\s*<\s*([0-9A-Za-z._/-]+)",
        rf"{re.escape(object_name)}\s*>\s*([0-9A-Za-z._/-]+)\s*&&\s*{re.escape(object_name)}\s*<=\s*([0-9A-Za-z._/-]+)",
        rf"{re.escape(object_name)}\s*>=\s*([0-9A-Za-z._/-]+)\s*&&\s*{re.escape(object_name)}\s*<=\s*([0-9A-Za-z._/-]+)",
    ]
    for pattern in between_patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            raw = match.group(0)
            lower_operator = "≤" if ">=" in raw.split("&&")[0] else "<"
            upper_operator = "≤" if "<=" in raw.split("&&")[1] else "<"
            line = build_version_range_line(
                lower=match.group(1),
                lower_op=lower_operator,
                object_name=object_name,
                upper_op=upper_operator,
                upper=match.group(2),
            )
            if line and line not in lines:
                lines.append(line)

    single_patterns = [
        (rf"{re.escape(object_name)}\s*<\s*([0-9A-Za-z._/-]+)", "<"),
        (rf"{re.escape(object_name)}\s*<=\s*([0-9A-Za-z._/-]+)", "≤"),
        (rf"{re.escape(object_name)}\s+before\s+([0-9A-Za-z._/-]+)", "<"),
    ]
    for pattern, upper_op in single_patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            upper = match.group(1)
            if introduced_match:
                lower = introduced_match.group(1)
                lower_op = "≤"
            else:
                return "请参考官方通告确认受影响范围。"
            line = build_version_range_line(lower, lower_op, object_name, upper_op, upper)
            if line and line not in lines:
                lines.append(line)

    if lines:
        return "\n".join(lines)
    return "请参考官方通告确认受影响范围。"


def extract_affected_versions(
    fields: dict[str, str],
    sections: dict[str, str],
    reference_text: str,
    object_name: str,
) -> str:
    """Extract affected version ranges, preferring official reference content over article prose."""
    preferred_sources = [
        sections.get("affected_versions_text", ""),
        fields.get("影响版本", ""),
        fields.get("受影响版本", ""),
        reference_text,
        sections.get("plain_text", ""),
    ]
    for source in preferred_sources:
        formatted = format_affected_versions(source, object_name)
        if formatted != "请参考官方通告确认受影响范围。":
            return formatted

    candidates = [
        sections.get("affected_versions_text", ""),
        fields.get("影响版本", ""),
        fields.get("受影响版本", ""),
    ]
    patterns = [
        rf"{re.escape(object_name)}\s+before\s+[0-9A-Za-z._-]+",
        rf"{re.escape(object_name)}\s*>\s*[0-9A-Za-z._-]+\s*&&\s*{re.escape(object_name)}\s*<\s*[0-9A-Za-z._-]+",
        rf"{re.escape(object_name)}\s*<\s*[0-9A-Za-z._-]+",
        rf"{re.escape(object_name)}\s*<=\s*[0-9A-Za-z._-]+",
        rf"{re.escape(object_name)}\s*=\s*[0-9A-Za-z._-]+\s*或更高版本",
        r"受影响的软件版本[:：]?\s*([^\n。]+)",
        r"Affected versions[:：]?\s*([^\n。]+)",
    ]
    for source in (reference_text, sections.get("plain_text", ""), sections.get("affected_versions_text", "")):
        for pattern in patterns:
            match = re.search(pattern, source, flags=re.IGNORECASE)
            if not match:
                continue
            value = sanitize_whitespace(match.group(0 if match.lastindex is None else 1))
            if value:
                candidates.append(value)
    for candidate in candidates:
        text = sanitize_whitespace(candidate)
        if not text:
            continue
        lowered = text.lower()
        if "升级" in lowered or "download" in lowered or "下载地址" in lowered:
            continue
        formatted = format_affected_versions(text, object_name)
        if formatted != "请参考官方通告确认受影响范围。":
            return formatted
    return "请参考官方通告确认受影响范围。"


def extract_fixed_versions(reference_text: str, security_update: str, object_name: str) -> str:
    """Extract the patched version string for remediation guidance."""
    patterns = [
        rf"{re.escape(object_name)}\s*>=\s*[0-9A-Za-z._-]+",
        rf"fixed as of\s+{re.escape(object_name)}\s*[0-9A-Za-z._-]+",
        rf"Patched versions?\s*([^\n。]+)",
        rf"升级至最新版本[:：]?\s*([^\n。]+)",
        rf"升级至\s*v?([0-9A-Za-z._-]+)\s*或更高版本",
        rf"更新至\s*v?([0-9A-Za-z._-]+)\s*或更高版本",
        rf"升级到\s*v?([0-9A-Za-z._-]+)\s*或更高版本",
        rf"修复版本[:：]?\s*v?([0-9A-Za-z._-]+)",
    ]
    for source in (security_update, reference_text):
        for pattern in patterns:
            match = re.search(pattern, source, flags=re.IGNORECASE)
            if not match:
                continue
            value = sanitize_whitespace(match.group(0 if match.lastindex is None else 1))
            if value:
                if re.fullmatch(r"v?[0-9A-Za-z._-]+", value, flags=re.IGNORECASE):
                    value = f"{normalize_version_token(value)} 及以上版本"
                return value
    return ""


def infer_fixed_versions_from_affected_ranges(affected_versions: str) -> str:
    """Infer patched-version lines from one-sided affected ranges when no explicit fixed version is present."""
    lines = [sanitize_whitespace(line) for line in (affected_versions or "").splitlines() if sanitize_whitespace(line)]
    inferred: list[str] = []
    for line in lines:
        match = re.fullmatch(r"(.+?)\s*(<|≤)\s*([0-9A-Za-z._-]+)", line)
        if not match:
            continue
        component_text = sanitize_whitespace(match.group(1)).replace("（", "(").replace("）", ")")
        operator = ">=" if match.group(2) == "<" else ">"
        version = normalize_version_token(match.group(3))
        inferred.append(f"{component_text} {operator} {version}")
    return "\n".join(dict.fromkeys(inferred))


def normalize_timeline_text(value: str, publish_date: str) -> str:
    """Normalize timeline text to the required date-only format."""
    return convert_date_formats(publish_date)[1]


def normalize_object_name(value: str) -> str:
    """Keep only the major component name without bracketed submodules."""
    text = sanitize_whitespace(value or "")
    text = re.sub(r"\s*[\(\（][^\)\）]*[\)\）]\s*", "", text)
    return sanitize_whitespace(text)


def simplify_attack_type(vulner_type: str) -> str:
    """Reduce verbose vulnerability type labels to the core attack-type phrase."""
    text = sanitize_whitespace(vulner_type or "")
    text = re.sub(r"\s*[\(\（][^\)\）]*[\)\）]\s*", "", text)
    return text


def normalize_vulnerability_name(vulner_name: str, object_name: str, vulner_type: str) -> str:
    """Align the generated vulnerability name with the selected component and attack type."""
    name = sanitize_whitespace(vulner_name or "")
    component = normalize_object_name(object_name)
    attack_type = simplify_attack_type(vulner_type)
    if not attack_type:
        return name
    if attack_type in name:
        return name
    suffix_patterns = [
        r"(远程代码执行|代码执行|命令执行|沙箱逃逸|权限提升|提权|信息泄露|SQL注入|任意文件读取|任意文件写入|文件上传|释放后重用|越界访问)漏洞$",
        r"(远程代码执行|代码执行|命令执行|沙箱逃逸|权限提升|提权|信息泄露|SQL注入|任意文件读取|任意文件写入|文件上传|释放后重用|越界访问)$",
    ]
    for pattern in suffix_patterns:
        if re.search(pattern, name):
            return re.sub(pattern, f"{attack_type}漏洞", name)
    return name


def normalize_solution_text(value: str) -> str:
    """Reflow remediation text into stable multi-line output."""
    text = (value or "").strip()
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{2,}", "\n", text).strip()
    text = re.sub(r"\s*(修复版本：)", r"\n\1", text)
    text = re.sub(r"\s*(升级方式：)", r"\n\1", text)
    text = re.sub(r"\s*(下载链接：|下载地址：)", r"\n\1", text)
    text = re.sub(r"\n{2,}", "\n", text).strip()
    return text


def extract_download_links(reference_links: list[str], reference_text: str, security_update: str = "") -> list[str]:
    """Extract download or release links, preferring GitHub releases URLs."""
    links = []
    found = re.findall(r"https?://[^\s<>\])]+", f"{reference_text}\n{security_update}")
    for link in list(reference_links) + found:
        cleaned = link.rstrip(").,]）")
        if cleaned not in links:
            links.append(cleaned)
    release_links = [link for link in links if "/releases/" in link or "/releases/tag/" in link]
    if release_links:
        return release_links[:3]
    download_links = [link for link in links if "download" in link.lower()]
    if download_links:
        return download_links[:3]
    return links[:3]


def infer_component_name(vulnerability_name: str, title: str) -> str:
    """Infer the main affected component name from the vulnerability title."""
    for candidate in (vulnerability_name, title):
        english_match = re.search(r"([A-Za-z][A-Za-z0-9._+-]{1,39})(?=[\u4e00-\u9fa5]|\b)", candidate)
        if english_match:
            return english_match.group(1)
        chinese_match = re.match(r"([\u4e00-\u9fa5A-Za-z0-9._+-]{2,40})", candidate)
        if chinese_match:
            value = chinese_match.group(1)
            value = re.sub(r"(浏览器|组件|系统|平台)$", "", value)
            value = re.sub(r"(漏洞|高危|远程|代码执行|命令执行|注入|信息泄露|沙箱逃逸|提权).*", "", value)
            value = value.strip()
            if value:
                return value
    return "目标组件"


def summarize_vulnerability_description(
    object_name: str,
    vulnerability_type: str,
    plain_text: str,
    reference_text: str,
) -> str:
    """Rewrite a concise vulnerability description instead of copying the source text."""
    combined = f"{plain_text} {reference_text}"
    if all(keyword in combined for keyword in ["build_public_tmp", "data 参数", "exec()"]):
        return (
            f"{object_name} 的公共流程构建端点 POST /api/v1/build_public_tmp/{{flow_id}}/flow "
            "允许未认证访问。漏洞场景下，当请求携带 data 参数时，服务端会直接使用攻击者提交的流程数据，"
            "而不是读取数据库中的既有流程，并在构建阶段通过 exec() 执行其中嵌入的 Python 代码。"
            "由于该流程缺少有效校验和沙箱隔离，攻击者可借助恶意流程定义触发远程代码执行。"
        )
    if all(keyword in reference_text for keyword in ["P_MLE", "%{expr}", "autocmd_add", "sandbox"]):
        return (
            f"{object_name} 在处理 tabpanel 相关模式行时缺少必要的安全限制，"
            "攻击者可借助未受限的 %{expr} 表达式注入恶意逻辑。"
            "参考资料显示，该漏洞链路与 P_MLE 标志缺失及 autocmd_add() 未执行安全校验有关，"
            "导致原本应受沙箱约束的行为在沙箱退出后仍可触发命令执行。"
        )
    if "modeline" in reference_text.lower() and "crafted file" in reference_text.lower():
        return (
            f"{object_name} 在解析 modeline 相关内容时存在安全边界缺失，"
            "攻击者可通过构造恶意文件在组件打开文件过程中触发表达式求值或后续命令执行逻辑。"
            "该问题使受害者在默认配置下仅通过打开文件即可落入攻击链。"
        )
    if "打开特制文件" in combined or "打开恶意文件" in combined:
        return (
            f"{object_name} 在处理攻击者构造的恶意文件时存在 {vulnerability_type} 风险，"
            "漏洞会在文件被打开或解析的阶段触发，使本地环境在缺少额外交互的情况下执行未授权命令。"
        )
    if "模式行" in combined or "tabpanel" in combined:
        return (
            f"{object_name} 在解析特定模式行配置时缺少必要的安全限制，"
            f"攻击者可借助精心构造的输入触发 {vulnerability_type}，并绕过原本应有的安全边界。"
        )
    return (
        f"{object_name} 在处理外部输入的过程中存在 {vulnerability_type} 风险，"
        "攻击者可通过构造恶意请求、文件或参数触发未授权行为，进而扩大对目标环境的控制能力。"
    )


def split_sentences(text: str) -> list[str]:
    """Split mixed Chinese/English prose into short sentences for heuristic summarization."""
    normalized = remove_source_mentions(text or "")
    normalized = normalized.replace("\n", " ")
    parts = re.split(r"(?<=[。！？!?；;])\s+|(?<=\.)\s+(?=[A-Z0-9])", normalized)
    return [sanitize_whitespace(part) for part in parts if sanitize_whitespace(part)]


def build_vulnerability_fact_snippets(vulnerability_text: str, reference_text: str) -> list[str]:
    """Collect high-signal technical sentences from article and references."""
    keyword_groups = [
        ("端点", "endpoint", "api", "路由"),
        ("参数", "parameter", "参数"),
        ("exec", "system(", "runtime.getruntime", "cmd.exe"),
        ("skia", "atlas", "plot", "mask", "越界", "越界访问"),
        ("modeline", "tabpanel", "%{expr}", "sandbox", "autocmd"),
        ("未授权", "无需认证", "未经身份验证", "unauthenticated"),
        ("文件", "crafted file", "恶意文件"),
        ("注入", "反序列化", "沙箱逃逸", "代码执行", "命令执行"),
    ]
    snippets: list[str] = []
    for sentence in split_sentences(f"{vulnerability_text} {reference_text}"):
        lowered = sentence.lower()
        if any(noise in lowered for noise in ["漏洞复现", "已成功复现", "复现该漏洞", "截图如下"]):
            continue
        if any(any(keyword in lowered for keyword in group) for group in keyword_groups):
            if sentence not in snippets:
                snippets.append(sentence)
    return snippets[:6]


def rewrite_vulnerability_description_with_ai(
    client: OpenAI,
    object_name: str,
    vulnerability_type: str,
    vulnerability_text: str,
    reference_text: str,
) -> str:
    """Use a focused LLM prompt to rewrite the technical vulnerability description."""
    snippets = build_vulnerability_fact_snippets(vulnerability_text, reference_text)
    user_payload = {
        "object_name": object_name,
        "vulnerability_type": vulnerability_type,
        "article_vulnerability_text": vulnerability_text[:3000],
        "reference_text": reference_text[:4000],
        "technical_snippets": snippets,
    }
    response = create_llm_completion(
        client,
        [
            {"role": "system", "content": VULNER_DESC_PROMPT},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
        temperature=0.2,
    )
    content = sanitize_whitespace(extract_llm_message_content(response))
    return remove_source_mentions(content)


def rewrite_component_description_with_ai(
    client: OpenAI,
    object_name: str,
    component_text: str,
    intro_text: str,
    reference_text: str,
) -> str:
    """Use a focused LLM prompt to generate a short component introduction."""
    user_payload = {
        "object_name": object_name,
        "component_text": component_text[:2000],
        "intro_text": intro_text[:2000],
        "reference_text": reference_text[:3000],
    }
    response = create_llm_completion(
        client,
        [
            {"role": "system", "content": OBJECT_DESC_PROMPT},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
        temperature=0.2,
    )
    content = sanitize_whitespace(extract_llm_message_content(response))
    return remove_source_mentions(content)


def rewrite_vulnerability_name_with_ai(
    client: OpenAI,
    title: str,
    table_fields: dict[str, str],
) -> str:
    """Use a focused LLM prompt to normalize the vulnerability name into a formal report style."""
    user_payload = {
        "title": title,
        "table_vulnerability_name": table_fields.get("漏洞名称", ""),
        "object_name": infer_component_name(table_fields.get("漏洞名称", "") or title, title),
        "vulnerability_type": table_fields.get("漏洞类型") or table_fields.get("威胁类型") or "",
    }
    response = create_llm_completion(
        client,
        [
            {"role": "system", "content": VULNER_NAME_PROMPT},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
        temperature=0.1,
    )
    content = sanitize_whitespace(extract_llm_message_content(response))
    return remove_source_mentions(content)


def rewrite_vulnerability_description_heuristically(
    object_name: str,
    vulnerability_type: str,
    vulnerability_text: str,
    reference_text: str,
) -> str:
    """Rewrite vulnerability details without an LLM by compressing extracted technical facts."""
    combined = f"{vulnerability_text} {reference_text}"
    lowered = combined.lower()

    if any(keyword in lowered for keyword in ["request-side prompt injection", "提示词注入"]) and any(
        keyword in lowered for keyword in ["上游 api", "完整性校验", "agent"]
    ):
        return (
            f"{object_name} 在处理上游 API 返回内容和请求侧提示词时缺少有效的完整性校验，"
            "攻击者可构造恶意提示词污染任务上下文。"
            "当被污染的指令进入 Agent 执行链后，平台可能被诱导执行本地文件篡改、依赖安装或系统命令调用，"
            f"最终在服务器侧形成{vulnerability_type}。"
        )

    if all(keyword in lowered for keyword in ["skia", "atlas", "plot"]):
        return (
            f"{object_name} 的 Skia 字符渲染链路在处理不同 Mask 类型的图集数据时存在边界校验缺失。"
            "攻击场景下，若渲染阶段使用的遮罩类型与字符预存信息不一致，程序会按错误的 Page-Plot 坐标访问目标图集，"
            "从而触发越界访问，并进一步形成沙箱逃逸利用条件。"
        )

    if "unicode_string" in lowered or ("邮件槽" in combined and "长度" in combined):
        parts = []
        if "邮件槽" in combined:
            parts.append(f"{object_name} 在处理邮件槽相关 UNC 路径请求时存在异常输入处理缺陷")
        else:
            parts.append(f"{object_name} 在处理特定请求路径和内部字符串结构时存在长度计算缺陷")
        if "unicode_string" in lowered:
            parts.append("漏洞链路中，程序在构造 UNICODE_STRING 结构时未正确扣减已跳过字符，导致长度字段与实际缓冲区不一致")
        if any(keyword in combined for keyword in ["读取越界", "越界读取", "缓冲区"]):
            parts.append("后续比较或访问操作可能据此触发越界读取，并进一步引发信息泄露、拒绝服务或权限提升风险")
        return "。".join(parts).rstrip("。") + "。"

    snippets = build_vulnerability_fact_snippets(vulnerability_text, reference_text)
    if snippets:
        first = remove_source_mentions(snippets[0])
        facts: list[str] = []
        if any(keyword in first for keyword in ["越界", "溢出", "边界"]):
            facts.append(f"{object_name} 在处理特定输入时存在边界校验缺陷")
        if "参数" in first or "请求" in first or "路径" in first:
            facts.append("攻击者可通过构造恶意请求、参数或路径触发异常处理流程")
        if any(keyword in first for keyword in ["代码执行", "命令执行", "权限提升", "沙箱逃逸", "信息泄露", "拒绝服务"]):
            facts.append(f"异常状态可进一步导致{vulnerability_type}或相关安全影响")
        if facts:
            return "。".join(dict.fromkeys(facts)).rstrip("。") + "。"

    return summarize_vulnerability_description(object_name, vulnerability_type, vulnerability_text, reference_text)


def summarize_component_description(object_name: str, plain_text: str, reference_text: str) -> str:
    """Generate a brief component introduction unrelated to the vulnerability impact."""
    source = f"{plain_text}\n{reference_text}"
    if object_name.lower() == "vim":
        return (
            "Vim 是一款跨平台文本编辑器，广泛用于代码编写、配置文件修改和终端环境下的文本处理。"
            "该项目长期用于开发、运维和系统管理等场景，并支持脚本扩展、插件管理和复杂编辑能力。"
        )
    if object_name.lower() == "openclaw" or ("agent" in source.lower() and "上游 api" in source.lower()):
        return (
            "OpenClaw 是一款面向 AI Agent 场景的自动化执行平台，可接收任务请求、调用上游模型或外部接口，并驱动本地工具与系统操作。"
            "该类平台通常用于把自然语言任务转化为可执行流程，以支持自动化处理、编排和代理执行。"
        )
    if object_name.lower() == "langflow" or "低代码可视化框架" in source:
        return (
            "Langflow 是一个基于 Python 和 FastAPI 构建的开源低代码可视化框架，常用于编排 AI 工作流、RAG 应用及多智能体系统。"
            "它通常通过图形化方式组织模型调用、数据处理与节点执行逻辑，以降低 AI 应用构建门槛。"
        )
    if "文本编辑器" in source:
        return (
            f"{object_name} 是一款文本编辑组件，常用于代码、配置和文档内容的编辑与处理。"
            "该类软件通常具备脚本扩展、格式处理和交互式编辑能力，并广泛用于研发和运维场景。"
        )
    if "浏览器" in source:
        return (
            f"{object_name} 是一类面向终端用户的软件组件，用于访问、解析和展示网络内容。"
            "该类软件通常同时承担渲染、脚本执行、页面交互和安全隔离等职责，是终端侧核心应用之一。"
        )
    if "框架" in source:
        return (
            f"{object_name} 是一款软件开发框架，通常用于承载业务逻辑、请求处理和数据交互。"
            "这类框架常被用于构建上层应用或服务，并提供基础能力封装、流程编排和扩展接口。"
        )
    return (
        f"{object_name} 是一款应用组件或平台软件，可用于承载业务逻辑处理、接口调用或相关功能扩展。"
        "该类软件通常部署于终端或服务器环境中，并与其他系统、服务或工具形成协作关系。"
    )


def summarize_hazard_description(
    object_name: str,
    plain_text: str,
    vuln_level: str,
    vulnerability_type: str = "",
) -> str:
    """Rewrite a concise hazard summary for the template."""
    level_prefix = "高危"
    if "中危" in vuln_level:
        level_prefix = "中危"
    elif "低危" in vuln_level:
        level_prefix = "低危"

    combined = f"{vulnerability_type} {plain_text}".lower()
    if any(keyword in combined for keyword in ["命令执行", "command execution"]):
        return strip_trailing_sentence_punct(
            f"{level_prefix}，可导致命令执行"
        )
    if any(keyword in combined for keyword in ["代码执行", "rce", "remote code execution", "exec()"]):
        return strip_trailing_sentence_punct(
            f"{level_prefix}，可导致代码执行"
        )
    if any(keyword in combined for keyword in ["服务器失陷", "主机控制", "系统控制权", "完全控制"]):
        return strip_trailing_sentence_punct(
            f"{level_prefix}，可导致服务器失陷"
        )
    if any(keyword in combined for keyword in ["信息泄露", "敏感信息", "info leak", "information disclosure"]):
        return strip_trailing_sentence_punct(
            f"{level_prefix}，可导致敏感信息泄露"
        )
    if "任意代码" in plain_text:
        return strip_trailing_sentence_punct(
            f"{level_prefix}，可导致代码执行"
        )
    return strip_trailing_sentence_punct(
        f"{level_prefix}，可导致 {object_name} 受影响环境存在被进一步控制的风险"
    )


def summarize_solution_text(fixed_versions: str, download_links: list[str], security_update: str = "") -> str:
    """Rewrite remediation guidance, handling both explicit versions and patch-selection workflows."""
    link_text = download_links[0] if download_links else ""
    if fixed_versions and link_text:
        return (
            "建议尽快升级至官方已发布的安全版本。\n"
            f"修复版本：{fixed_versions}\n"
            f"下载链接：{link_text}"
        )
    if fixed_versions:
        return (
            "建议尽快升级至官方已发布的安全版本。\n"
            f"修复版本：{fixed_versions}\n"
            "下载链接：请使用官方发布渠道获取对应修复版本。"
        )
    lowered_update = (security_update or "").lower()
    if link_text and any(keyword in lowered_update for keyword in ["windows update", "补丁", "microsoft update", "更新目录"]):
        return (
            "建议尽快按照官方补丁指引完成修复。\n"
            "修复方式：请根据目标系统版本在官方公告页选择对应补丁安装。\n"
            f"下载链接：{link_text}"
        )
    if link_text:
        return (
            "建议尽快按照官方修复指引完成升级。\n"
            "修复方式：请参考官方公告页提供的修复指引。\n"
            f"下载链接：{link_text}"
        )
    return (
        "建议尽快按照官方修复指引完成升级。\n"
        "修复方式：请参考官方公告页提供的修复指引。\n"
        "下载链接：请使用官方发布渠道获取对应修复版本。"
    )


def build_unique_reference_fields(download_links: list[str], reference_links: list[str]) -> tuple[str, str, str]:
    """Assign reference fields from a de-duplicated ordered link list."""
    unique_links: list[str] = []
    for link in list(download_links) + list(reference_links):
        cleaned = sanitize_whitespace(link)
        if cleaned and cleaned not in unique_links:
            unique_links.append(cleaned)
    return (
        unique_links[0] if len(unique_links) > 0 else "",
        unique_links[1] if len(unique_links) > 1 else "",
        unique_links[2] if len(unique_links) > 2 else "",
    )


def map_cvss_to_level(cvss_text: str) -> str:
    """Map a numeric CVSS score to a Chinese severity level."""
    match = re.search(r"(\d+(?:\.\d+)?)", cvss_text or "")
    if not match:
        return "高危"
    score = float(match.group(1))
    if score >= 9.0:
        return "严重"
    if score >= 7.0:
        return "高危"
    if score >= 4.0:
        return "中危"
    return "低危"


def infer_user_auth(plain_text: str, reference_text: str) -> str:
    """Infer whether exploitation requires authentication, prioritizing explicit unauthenticated wording."""
    combined = f"{plain_text}\n{reference_text}".lower()

    unauthenticated_patterns = [
        r"\bunauthenticated\b",
        r"without requiring authentication",
        r"without authentication",
        r"no authentication",
        r"does not require authentication",
        r"无需认证",
        r"不需要用户认证",
        r"无需登录",
        r"未授权",
        r"未经身份验证",
    ]
    for pattern in unauthenticated_patterns:
        if re.search(pattern, combined, flags=re.IGNORECASE):
            return "不需要用户认证"

    authenticated_patterns = [
        r"\brequires authentication\b",
        r"\brequire authentication\b",
        r"\bauthenticated user\b",
        r"\bafter login\b",
        r"\blogged-in user\b",
        r"需要用户认证",
        r"需要认证",
        r"需要登录",
        r"登录后",
        r"认证用户",
    ]
    for pattern in authenticated_patterns:
        if re.search(pattern, combined, flags=re.IGNORECASE):
            return "需要用户认证"

    return "不需要用户认证"


def build_heuristic_payload(
    title: str,
    publish_date: str,
    fields: dict[str, str],
    sections: dict[str, str],
    reference_links: list[str],
    reference_materials: list[dict[str, str]],
) -> dict[str, str]:
    """Build a conservative fallback payload when no LLM runtime is available."""
    reference_text = build_reference_text(reference_materials)
    vulner_name = fields.get("漏洞名称") or title
    identifiers = extract_identifiers(title, fields)
    vulner_number = identifiers[0] if identifiers else ""
    object_name = infer_component_name(vulner_name, title)
    vulner_type = fields.get("漏洞类型") or fields.get("威胁类型") or "远程代码执行"
    use_auth = infer_user_auth(sections["plain_text"], reference_text)
    pre_condition = "默认配置"
    if "打开特制文件" in sections["plain_text"] or "opens a crafted file" in reference_text.lower():
        pre_condition = "需要用户打开恶意构造的文件"
    elif "特定配置" in sections["plain_text"] or "requires" in reference_text.lower():
        pre_condition = "需要满足特定配置要求"
    trigger_mode = "本地"
    if any(keyword in reference_text.lower() for keyword in ["remote", "network", "over the network", "remote attacker"]):
        trigger_mode = "远程"
    utilize_difficulty = fields.get("利用可能性") or ("低" if "已复现" in title or "已公开" in sections["plain_text"] else "中")
    vuln_level = map_cvss_to_level(fields.get("CVSS 3.1", "") or fields.get("CVSS 3.1分数", ""))
    hazard_level = summarize_hazard_description(object_name, sections["plain_text"], vuln_level, vulner_type)
    object_desc = summarize_component_description(
        object_name,
        sections.get("component_text") or sections["intro_text"] or sections["plain_text"],
        reference_text,
    )
    vulnerability_source_text = sections.get("vulnerability_text") or sections["plain_text"]
    vulner_desc = rewrite_vulnerability_description_heuristically(
        object_name,
        vulner_type,
        vulnerability_source_text,
        reference_text,
    )
    vulner_version = extract_affected_versions(fields, sections, reference_text, object_name)
    fixed_versions = extract_fixed_versions(reference_text, sections["security_update"], object_name)
    if not fixed_versions:
        fixed_versions = infer_fixed_versions_from_affected_ranges(vulner_version)
    download_links = extract_download_links(reference_links, reference_text, sections["security_update"])
    official_solution = summarize_solution_text(fixed_versions, download_links, sections.get("security_update", ""))
    reference_link, reference_link1, reference_link2 = build_unique_reference_fields(download_links, reference_links)
    vulner_date, vulner_time_line = convert_date_formats(publish_date)
    payload = {
        "vulner_name": vulner_name,
        "vulner_number_1": vulner_number,
        "vulner_number_2": "",
        "new_vulner_name": vulner_name,
        "vulner_date": vulner_date,
        "vulner_time_line": vulner_time_line,
        "object_name": object_name,
        "object_desc": object_desc,
        "vulner_version": vulner_version,
        "vulner_type": vulner_type,
        "user_auth": use_auth,
        "pre_condition": pre_condition,
        "trigger_mode": trigger_mode,
        "utilize_difficulty": utilize_difficulty,
        "hazard_level": hazard_level,
        "vuln_level": vuln_level,
        "vulner_desc": vulner_desc,
        "official_solution": official_solution,
        "reference_link": reference_link,
        "reference_link1": reference_link1,
        "reference_link2": reference_link2,
    }
    return payload


def llm_ready() -> bool:
    """Return whether the required LLM environment variables are available."""
    return bool(os.environ.get("llm_url") and os.environ.get("llm_api_key"))


def create_llm_client() -> OpenAI:
    """Create an OpenAI-compatible client from the current environment."""
    return OpenAI(base_url=os.environ["llm_url"], api_key=os.environ["llm_api_key"])


def create_llm_completion(client: OpenAI, messages: list[dict[str, str]], temperature: float = 0.2) -> Any:
    """Create one chat completion using the MiniMax-compatible reasoning_split request shape."""
    return client.chat.completions.create(
        model=DEFAULT_MODEL,
        messages=messages,
        temperature=temperature,
        extra_body={"reasoning_split": True},
    )


def extract_llm_message_content(response: Any) -> str:
    """Extract assistant message content from an OpenAI-compatible response with explicit validation."""
    choices = getattr(response, "choices", None)
    if not choices:
        preview = repr(response)
        raise ValueError(f"模型响应缺少 choices: {preview[:500]}")
    first_choice = choices[0]
    message = getattr(first_choice, "message", None)
    if message is None:
        preview = repr(first_choice)
        raise ValueError(f"模型响应缺少 message: {preview[:500]}")
    content = getattr(message, "content", None)
    if content is None:
        preview = repr(message)
        raise ValueError(f"模型响应缺少 content: {preview[:500]}")
    return str(content)


def extract_llm_reasoning_text(response: Any) -> str:
    """Extract reasoning_details text when the backend returns split reasoning output."""
    choices = getattr(response, "choices", None)
    if not choices:
        return ""
    first_choice = choices[0]
    message = getattr(first_choice, "message", None)
    if message is None:
        return ""
    reasoning_details = getattr(message, "reasoning_details", None)
    if not reasoning_details:
        return ""
    parts: list[str] = []
    for item in reasoning_details:
        if isinstance(item, dict):
            text = item.get("text")
        else:
            text = getattr(item, "text", None)
        if text:
            parts.append(str(text))
    return sanitize_whitespace("\n".join(parts))


def parse_json_response(content: str) -> dict[str, Any]:
    """Parse a model response that may be wrapped in markdown code fences."""
    cleaned = content.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", cleaned, flags=re.DOTALL)
    if fenced:
        cleaned = fenced.group(1)

    # Some model backends prepend explanations or thoughts before the JSON body.
    if not cleaned.startswith("{"):
        first_brace = cleaned.find("{")
        if first_brace != -1:
            cleaned = cleaned[first_brace:]

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        obj, _ = decoder.raw_decode(cleaned)
        if isinstance(obj, dict):
            return obj
        raise


def call_llm_json(client: OpenAI, system_prompt: str, user_payload: dict[str, Any]) -> dict[str, Any]:
    """Run a JSON-only chat completion and return the parsed object."""
    base_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
    ]
    last_error: Exception | None = None
    last_content = ""
    for messages in (
        base_messages,
        base_messages
        + [
            {
                "role": "user",
                "content": "上一个回答不是合法 JSON。不要解释，不要代码块，只输出一个 JSON 对象。",
            }
        ],
    ):
        response = create_llm_completion(client, messages, temperature=0.2)
        content = extract_llm_message_content(response) or "{}"
        last_content = content
        try:
            return parse_json_response(content)
        except (json.JSONDecodeError, ValueError) as exc:
            last_error = exc
            continue
    preview = sanitize_whitespace(last_content)[:300]
    raise ValueError(f"模型未返回合法JSON，响应片段: {preview}") from last_error


def build_source_package(
    title: str,
    publisher: str,
    publish_date: str,
    table_fields: dict[str, str],
    sections: dict[str, str],
    reference_links: list[str],
    reference_materials: list[dict[str, str]],
) -> dict[str, Any]:
    """Build the structured source package used by the extraction stage."""
    return {
        "title": title,
        "publisher": publisher,
        "publish_date": publish_date,
        "table_fields": table_fields,
        "intro_text": sections["intro_text"],
        "security_update": sections["security_update"],
        "reference_links": reference_links,
        "reference_materials": reference_materials,
        "rules": {
            "user_auth": "只能填写“需要用户认证”或“不需要用户认证”",
            "pre_condition": "无特殊前置要求时填写“默认配置”",
            "trigger_mode": "只能填写“远程”或“本地”",
            "affected_versions": "必须是受影响范围，不能写修复版本",
            "official_solution": "必须附下载链接；如果有 GitHub releases 链接优先使用",
        },
    }


def build_llm_payload(
    title: str,
    publish_date: str,
    table_fields: dict[str, str],
    sections: dict[str, str],
    reference_links: list[str],
    reference_materials: list[dict[str, str]],
    verbose: bool = False,
) -> dict[str, str]:
    """Run the multi-stage LLM pipeline and return the final template payload."""
    client = create_llm_client()
    reference_text = build_reference_text(reference_materials)
    try:
        stage_log(verbose, "LLM阶段: facts")
        stage_started = perf_counter()
        facts = call_llm_json(
            client,
            FACTS_PROMPT,
            build_source_package(
                title=title,
                publisher="已脱敏来源",
                publish_date=publish_date,
                table_fields=table_fields,
                sections=sections,
                reference_links=reference_links,
                reference_materials=reference_materials,
            ),
        )
        stage_log(verbose, f"LLM阶段: facts 完成，耗时 {format_elapsed_seconds(stage_started)}")
    except Exception as exc:
        raise RuntimeError(f"LLM阶段 facts 失败: {exc}") from exc
    try:
        stage_log(verbose, "LLM阶段: rewrite_vulner_desc")
        stage_started = perf_counter()
        rewritten_vulner_desc = rewrite_vulnerability_description_with_ai(
            client,
            infer_component_name(table_fields.get("漏洞名称", "") or title, title),
            table_fields.get("漏洞类型") or table_fields.get("威胁类型") or "安全风险",
            sections.get("vulnerability_text") or sections["plain_text"],
            reference_text,
        )
        stage_log(verbose, f"LLM阶段: rewrite_vulner_desc 完成，耗时 {format_elapsed_seconds(stage_started)}")
    except Exception as exc:
        raise RuntimeError(f"LLM阶段 rewrite_vulner_desc 失败: {exc}") from exc
    try:
        stage_log(verbose, "LLM阶段: rewrite_object_desc")
        stage_started = perf_counter()
        rewritten_object_desc = rewrite_component_description_with_ai(
            client,
            infer_component_name(table_fields.get("漏洞名称", "") or title, title),
            sections.get("component_text") or "",
            sections.get("intro_text") or "",
            reference_text,
        )
        stage_log(verbose, f"LLM阶段: rewrite_object_desc 完成，耗时 {format_elapsed_seconds(stage_started)}")
    except Exception as exc:
        raise RuntimeError(f"LLM阶段 rewrite_object_desc 失败: {exc}") from exc
    try:
        stage_log(verbose, "LLM阶段: rewrite_vulner_name")
        stage_started = perf_counter()
        rewritten_vulner_name = rewrite_vulnerability_name_with_ai(
            client,
            title,
            table_fields,
        )
        stage_log(verbose, f"LLM阶段: rewrite_vulner_name 完成，耗时 {format_elapsed_seconds(stage_started)}")
    except Exception as exc:
        raise RuntimeError(f"LLM阶段 rewrite_vulner_name 失败: {exc}") from exc
    try:
        stage_log(verbose, "LLM阶段: payload")
        stage_started = perf_counter()
        payload = call_llm_json(
            client,
            PAYLOAD_PROMPT,
            {
                "facts": facts,
                "reference_links": reference_links[:3],
                "required_fields": [field["name"] for field in app.FIELD_DEFINITIONS],
            },
        )
        stage_log(verbose, f"LLM阶段: payload 完成，耗时 {format_elapsed_seconds(stage_started)}")
    except Exception as exc:
        raise RuntimeError(f"LLM阶段 payload 失败: {exc}") from exc
    if rewritten_vulner_desc:
        payload["vulner_desc"] = rewritten_vulner_desc
    if rewritten_object_desc:
        payload["object_desc"] = rewritten_object_desc
    if rewritten_vulner_name:
        payload["vulner_name"] = rewritten_vulner_name
        payload["new_vulner_name"] = rewritten_vulner_name
    return normalize_payload(
        payload,
        reference_links,
        publish_date,
        title,
        table_fields,
        sections,
        reference_text,
    )


def normalize_payload(
    payload: dict[str, Any],
    reference_links: list[str],
    publish_date: str,
    title: str,
    table_fields: dict[str, str],
    sections: dict[str, str],
    reference_text: str = "",
) -> dict[str, str]:
    """Normalize field types and patch missing defaults before template rendering."""
    normalized: dict[str, str] = {}
    download_links = extract_download_links(reference_links, reference_text, sections.get("security_update", ""))
    for field in app.FIELD_DEFINITIONS:
        name = field["name"]
        raw_value = str(payload.get(name, ""))
        if name in {"official_solution", "vulner_version", "vulner_time_line"}:
            normalized[name] = raw_value.strip()
        else:
            normalized[name] = sanitize_whitespace(raw_value)
    if not normalized["vulner_name"]:
        normalized["vulner_name"] = table_fields.get("漏洞名称") or title
    if not normalized["vulner_number_1"]:
        identifiers = extract_identifiers(title, table_fields)
        normalized["vulner_number_1"] = identifiers[0] if identifiers else ""
    if normalized["vulner_number_1"] and not normalized["vulner_number_1"].startswith("CVE-"):
        identifiers = extract_identifiers(title, table_fields)
        cve_identifiers = [item for item in identifiers if item.startswith("CVE-")]
        normalized["vulner_number_1"] = cve_identifiers[0] if cve_identifiers else ""
    normalized["new_vulner_name"] = normalized["vulner_name"]
    if not normalized["vulner_date"] or not normalized["vulner_time_line"]:
        vulner_date, vulner_time_line = convert_date_formats(publish_date)
        normalized["vulner_date"] = normalized["vulner_date"] or vulner_date
        normalized["vulner_time_line"] = normalized["vulner_time_line"] or vulner_time_line
    normalized["vulner_time_line"] = normalize_timeline_text(normalized["vulner_time_line"], publish_date)
    if not normalized["reference_link"]:
        normalized["reference_link"] = reference_links[0] if len(reference_links) > 0 else ""
        normalized["reference_link1"] = reference_links[1] if len(reference_links) > 1 else ""
        normalized["reference_link2"] = reference_links[2] if len(reference_links) > 2 else ""
    canonical_object_name = infer_component_name(
        table_fields.get("漏洞名称") or normalized["vulner_name"],
        title,
    )
    if not normalized["object_name"]:
        normalized["object_name"] = canonical_object_name
    normalized["object_name"] = normalize_object_name(normalized["object_name"])
    if normalized["object_desc"]:
        normalized["object_desc"] = remove_source_mentions(normalized["object_desc"])
    version_object_name = canonical_object_name or normalized["object_name"]
    normalized["vulner_version"] = format_affected_versions(normalized["vulner_version"], version_object_name)
    extracted_vulner_version = extract_affected_versions(
        table_fields,
        sections,
        reference_text,
        version_object_name,
    )
    if "请参考官方通告确认受影响范围。" in normalized["vulner_version"]:
        normalized["vulner_version"] = extracted_vulner_version
    else:
        current_lines = [line for line in normalized["vulner_version"].splitlines() if sanitize_whitespace(line)]
        extracted_lines = [line for line in extracted_vulner_version.splitlines() if sanitize_whitespace(line)]
        if extracted_lines and len(extracted_lines) > len(current_lines):
            normalized["vulner_version"] = extracted_vulner_version
    inferred_fixed_versions = infer_fixed_versions_from_affected_ranges(normalized["vulner_version"])
    if normalized["vulner_desc"]:
        normalized["vulner_desc"] = remove_source_mentions(normalized["vulner_desc"])
    if normalized["official_solution"]:
        normalized["official_solution"] = remove_source_mentions(normalized["official_solution"])
    if (
        (not normalized["official_solution"])
        or ("http" not in normalized["official_solution"].lower())
        or normalized["official_solution"].startswith("建议尽快升级")
        or any(
        marker in normalized["official_solution"]
        for marker in [
            "修复版本：请参考官方发布说明。",
            "修复方式：请参考官方公告页提供的修复指引。",
            "修复方式：请根据目标系统版本在官方公告页选择对应补丁安装。",
        ]
        )
    ):
        normalized["official_solution"] = summarize_solution_text(
            inferred_fixed_versions,
            download_links,
            sections.get("security_update", ""),
        )
    normalized["official_solution"] = normalize_solution_text(normalized["official_solution"])
    normalized["user_auth"] = infer_user_auth(sections["plain_text"], reference_text)
    if not normalized["pre_condition"]:
        normalized["pre_condition"] = "默认配置"
    if normalized["trigger_mode"] not in {"远程", "本地"}:
        normalized["trigger_mode"] = "本地"
    normalized["vulner_type"] = simplify_attack_type(normalized["vulner_type"])
    normalized["vulner_name"] = normalize_vulnerability_name(
        normalized["vulner_name"],
        normalized["object_name"],
        normalized["vulner_type"],
    )
    normalized["new_vulner_name"] = normalized["vulner_name"]
    return normalized


def validate_payload(payload: dict[str, Any], source_text: str) -> list[str]:
    """Validate generated payload against forbidden terms and copy risks."""
    issues: list[str] = []
    source_compare = normalize_compare_text(source_text)
    required_fields = [field["name"] for field in app.FIELD_DEFINITIONS if field["required"]]
    for field_name in required_fields:
        if not sanitize_whitespace(str(payload.get(field_name, ""))):
            issues.append(f"缺少必填字段: {field_name}")

    for field_name, value in payload.items():
        text = sanitize_whitespace(str(value))
        if not text:
            continue
        lowered = text.lower()
        for term in FORBIDDEN_SOURCE_TERMS:
            if term.lower() in lowered:
                issues.append(f"字段 {field_name} 含有禁用来源字样: {term}")
        if field_name in {"object_desc", "vulner_desc", "official_solution"}:
            compare = normalize_compare_text(text)
            if len(compare) >= 24 and compare in source_compare:
                issues.append(f"字段 {field_name} 疑似直接照抄原文")
    if payload.get("user_auth") not in {"需要用户认证", "不需要用户认证"}:
        issues.append("字段 user_auth 必须为“需要用户认证”或“不需要用户认证”")
    if not sanitize_whitespace(str(payload.get("pre_condition", ""))):
        issues.append("字段 pre_condition 不能为空，且无特殊要求时应为“默认配置”")
    if payload.get("trigger_mode") not in {"远程", "本地"}:
        issues.append("字段 trigger_mode 必须为“远程”或“本地”")
    official_solution = sanitize_whitespace(str(payload.get("official_solution", "")))
    if official_solution and "http" not in official_solution.lower():
        issues.append("字段 official_solution 必须包含下载链接")
    if "请参考官方通告确认受影响范围" in sanitize_whitespace(str(payload.get("vulner_version", ""))):
        issues.append("字段 vulner_version 不能输出占位文案，必须提取到明确影响范围")
    return issues


def write_debug_json(output_paths: dict[str, str], debug_payload: dict[str, Any]) -> str:
    """Write the intermediate debug JSON next to the generated documents."""
    notice_path = Path(output_paths["notice"])
    debug_path = notice_path.with_suffix(".json")
    debug_path.write_text(json.dumps(debug_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(debug_path)


def main() -> int:
    """Run the end-to-end demo pipeline and generate the two notice documents."""
    args = parse_args()
    stage_log(args.verbose, "开始解析输入")
    markdown_path, original_url = resolve_markdown_source(args.source)
    stage_log(args.verbose, f"已得到 markdown: {markdown_path}")
    markdown_text = load_markdown(markdown_path)
    stage_log(args.verbose, "开始提取文章结构")
    publisher = detect_publisher(markdown_text)
    title = extract_title(markdown_text)
    publish_date = extract_article_date(markdown_text)
    table_fields = extract_table_fields(markdown_text)
    sections = extract_plain_sections(markdown_text)
    reference_links = extract_reference_links(markdown_text)
    stage_log(args.verbose, f"已提取参考链接数量: {len(reference_links[:3])}")
    stage_log(args.verbose, "开始抓取参考链接正文")
    stage_started = perf_counter()
    reference_materials = collect_reference_materials(reference_links[:3])
    stage_log(args.verbose, f"抓取参考链接正文完成，耗时 {format_elapsed_seconds(stage_started)}")
    if not llm_ready():
        raise RuntimeError("缺少 LLM 环境变量: 请配置 llm_url 和 llm_api_key")
    mode = "llm"
    stage_log(args.verbose, "开始执行 LLM 流程")
    stage_started = perf_counter()
    payload = build_llm_payload(title, publish_date, table_fields, sections, reference_links, reference_materials, verbose=args.verbose)
    stage_log(args.verbose, f"LLM 流程完成，耗时 {format_elapsed_seconds(stage_started)}")

    stage_log(args.verbose, "开始规范化字段")
    payload = normalize_payload(
        payload,
        reference_links,
        publish_date,
        title,
        table_fields,
        sections,
        build_reference_text(reference_materials),
    )
    stage_log(args.verbose, "开始校验最终字段")
    issues = validate_payload(payload, sections["plain_text"])
    if issues:
        raise ValueError("生成字段校验失败: " + "; ".join(issues))

    stage_log(args.verbose, "开始生成 docx")
    stage_started = perf_counter()
    output_paths = app.generate_notice(payload)
    stage_log(args.verbose, f"docx 生成完成，耗时 {format_elapsed_seconds(stage_started)}")
    result = {
        "mode": mode,
        "publisher": publisher,
        "title": title,
        "article_url": original_url,
        "markdown_path": str(markdown_path),
        "reference_links": reference_links[:3],
        "notice": output_paths["notice"],
        "regulator_notice": output_paths["regulator_notice"],
    }

    if args.debug_json:
        result["debug_json"] = write_debug_json(
            output_paths,
            {
                "mode": mode,
                "title": title,
                "publisher": publisher,
                "publish_date": publish_date,
                "table_fields": table_fields,
                "sections": sections,
                "reference_links": reference_links,
                "reference_materials": reference_materials,
                "payload": payload,
            },
        )

    if not args.keep_md and original_url and markdown_path.exists():
        shutil.rmtree(markdown_path.parent.parent, ignore_errors=True)

    if args.compact:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
