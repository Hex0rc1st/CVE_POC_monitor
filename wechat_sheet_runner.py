#!/usr/bin/env python3
"""Poll the Wechat Google Sheet for new article URLs and run the document pipeline."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import msg_push

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / "utils" / "wechat_sheet_urls.txt"
ARTICLE_SCRIPT = BASE_DIR / "article" / "wechat_notice_demo.py"
WECHAT_FILE_DEMO = BASE_DIR / "wechat_file_demo.py"
SHEET_NAME = "Wechat"
URL_HEADER_CANDIDATES = ("url", "链接", "网址", "文章地址", "url列")


def canonicalize_wechat_link(link: str) -> str:
    """Normalize WeChat article links so the same article is not processed twice."""
    raw_link = str(link or "").strip()
    if not raw_link:
        return ""
    parsed = urlparse(raw_link)
    if "mp.weixin.qq.com" not in parsed.netloc:
        return raw_link
    if parsed.path.startswith("/s/"):
        return f"https://mp.weixin.qq.com{parsed.path}"
    query = parse_qs(parsed.query)
    preferred_keys = ["__biz", "mid", "idx", "sn"]
    filtered = [(key, query[key][0]) for key in preferred_keys if key in query and query[key]]
    if filtered:
        return f"https://mp.weixin.qq.com{parsed.path}?{urlencode(filtered)}"
    return f"https://mp.weixin.qq.com{parsed.path}"


def load_processed_urls() -> set[str]:
    """Load already processed sheet URLs from the local state file."""
    if not STATE_FILE.exists():
        return set()
    return {line.strip() for line in STATE_FILE.read_text(encoding="utf-8").splitlines() if line.strip()}


def append_processed_urls(urls: list[str]) -> None:
    """Append new processed URL markers to the local state file."""
    if not urls:
        return
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open("a", encoding="utf-8") as handle:
        for url in urls:
            handle.write(f"{url}\n")


def normalize_header_name(value: str) -> str:
    """Normalize one sheet header cell so URL column detection is stable."""
    return "".join(str(value or "").strip().lower().split())


def find_url_column_index(headers: list[str]) -> int:
    """Locate the URL column inside the Wechat sheet header row."""
    normalized_headers = [normalize_header_name(item) for item in headers]
    for candidate in URL_HEADER_CANDIDATES:
        normalized_candidate = normalize_header_name(candidate)
        if normalized_candidate in normalized_headers:
            return normalized_headers.index(normalized_candidate)
    raise ValueError(f"Wechat sheet 未找到 url 列，当前表头: {headers}")


def fetch_wechat_sheet_urls() -> list[dict[str, str]]:
    """Fetch and normalize article URLs from the Wechat Google Sheet."""
    table_content = msg_push.get_google_sheet(SHEET_NAME)
    if not table_content:
        logging.info("Wechat sheet 当前为空")
        return []
    headers = table_content[0]
    url_index = find_url_column_index(headers)
    rows: list[dict[str, str]] = []
    for row in table_content[1:]:
        if len(row) <= url_index:
            continue
        original_url = str(row[url_index]).strip()
        if not original_url.startswith("http"):
            continue
        rows.append(
            {
                "original_url": original_url,
                "canonical_url": canonicalize_wechat_link(original_url),
            }
        )
    return rows


def run_notice_generation(article_url: str) -> dict[str, str]:
    """Run the existing article generation script for one WeChat article URL."""
    command = ["python3", str(ARTICLE_SCRIPT), article_url, "--compact"]
    completed = subprocess.run(
        command,
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"文章生成脚本执行失败: returncode={completed.returncode}, stdout={completed.stdout}, stderr={completed.stderr}"
        )
    try:
        payload = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"文章生成脚本输出不是合法 JSON: {exc}; stdout={completed.stdout}") from exc
    if not payload.get("notice") or not payload.get("regulator_notice"):
        raise RuntimeError(f"文章生成脚本未返回完整文档路径: {payload}")
    return payload


def send_wechat_file(file_path: str) -> dict[str, object]:
    """Send one generated document to WeCom through the existing wrapper script."""
    command = ["python3", str(WECHAT_FILE_DEMO), str(file_path), "--compact"]
    completed = subprocess.run(
        command,
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"企微文件发送脚本执行失败: returncode={completed.returncode}, stdout={completed.stdout}, stderr={completed.stderr}"
        )
    try:
        payload = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"企微文件发送脚本输出不是合法 JSON: {exc}; stdout={completed.stdout}") from exc
    if not payload.get("ok"):
        raise RuntimeError(f"企微文件发送失败: {payload}")
    return payload


def cleanup_generated_documents(generation_payload: dict[str, str]) -> None:
    """Delete generated local documents so the workflow only persists state files."""
    for key in ("notice", "regulator_notice", "debug_json"):
        path_text = generation_payload.get(key, "")
        if not path_text:
            continue
        path = Path(path_text)
        if path.exists():
            path.unlink()
    notice_path = Path(generation_payload["notice"])
    parent_dir = notice_path.parent
    if parent_dir.exists() and not any(parent_dir.iterdir()):
        parent_dir.rmdir()


def process_one_sheet_url(article_url: str) -> None:
    """Generate documents for one sheet URL and send both files to WeCom."""
    generation_payload = run_notice_generation(article_url)
    send_wechat_file(generation_payload["notice"])
    send_wechat_file(generation_payload["regulator_notice"])
    cleanup_generated_documents(generation_payload)


def main() -> int:
    """Process newly added URLs from the Wechat sheet."""
    logging.basicConfig(level=logging.INFO)
    logging.info("开始处理 Wechat sheet 新增文章")
    sheet_rows = fetch_wechat_sheet_urls()
    if not sheet_rows:
        logging.info("Wechat sheet 未发现可处理 URL")
        return 0

    processed_urls = load_processed_urls()
    current_markers: list[str] = []
    deduped_rows: list[dict[str, str]] = []
    seen_this_run: set[str] = set()
    for row in sheet_rows:
        markers = [row["original_url"], row["canonical_url"]]
        current_markers.extend([item for item in markers if item])
        identity = row["canonical_url"] or row["original_url"]
        if identity in seen_this_run:
            continue
        seen_this_run.add(identity)
        deduped_rows.append(row)

    if not STATE_FILE.exists():
        append_processed_urls(list(dict.fromkeys(current_markers)))
        logging.info("Wechat sheet 首次初始化，已记录当前 URL 并跳过历史")
        return 0

    pending_rows = []
    for row in deduped_rows:
        markers = {row["original_url"], row["canonical_url"]}
        if any(marker and marker in processed_urls for marker in markers):
            continue
        pending_rows.append(row)

    if not pending_rows:
        logging.info("Wechat sheet 未发现新增 URL")
        return 0

    logging.info("Wechat sheet 新增 URL 数量: %s", len(pending_rows))
    for row in pending_rows:
        article_url = row["original_url"]
        logging.info("开始处理 Wechat sheet URL: %s", article_url)
        process_one_sheet_url(article_url)
        append_processed_urls([row["original_url"], row["canonical_url"]])
        processed_urls.update({row["original_url"], row["canonical_url"]})
        logging.info("完成处理 Wechat sheet URL: %s", article_url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
