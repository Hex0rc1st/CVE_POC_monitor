#!/usr/bin/env python 
# -*- coding: utf-8 -*-
# @Time    : 2025/03/04
# @Author  : LXY
# @File    : main.py
# @Github: https://github.com/MMarch7
import datetime
import feedparser
import json
import logging
import os
import subprocess
import time
#import dingtalkchatbot.chatbot as cb
import requests
import re
import xml.etree.ElementTree as ET
import yaml
import tempfile
import shutil
import platform
import utils.load
from cve_lookup_api import build_cve_response
from utils.advisory_match import allowed_advisory_severities
from utils.advisory_match import build_advisory_search_fields
from utils.advisory_match import extract_advisory_key
from urllib.parse import quote
from pathlib import Path
import msg_push
import csv
from utils.advisory_match import match_known_object
from urllib.parse import urlparse, parse_qs, urlencode

github_token = os.environ.get("github_token")
repo_list,keywords,user_list = utils.load.load_tools_list()
wechat_sources = utils.load.load_wechat_sources()
CleanKeywords = utils.load.load_clean_list()
known_object = utils.load.load_object_list()
github_sha = "./utils/sha.txt"
github_advisory_sha = "./utils/advisory_sha.txt"
github_advisory_ids = "./utils/advisory_ids.txt"
github_repo_sha_dir = "./utils/repo_shas"
wechat_articles_state = "./utils/wechat_articles.txt"
wechat_source_state = "./utils/wechat_source_latest.json"

WXRSS_RAW_BASE = "https://raw.githubusercontent.com/0xlane/wxrss_static/main"
DOONSEC_WECHAT_RSS = "https://wechat.doonsec.com/rss.xml"
BRUCE_PICKER_DAILY = "https://raw.githubusercontent.com/BruceFeIix/picker/refs/heads/master/archive/daily/{year}/{date}.md"
CHAINREACTORS_PICKER_DAILY = "https://raw.githubusercontent.com/chainreactors/picker/refs/heads/master/archive/daily/{year}/{date}.md"
WECHAT_MAX_PENDING_PER_SOURCE = 3
ARTICLE_DIR = Path(__file__).resolve().parent / "article"
ARTICLE_NOTICE_SCRIPT = ARTICLE_DIR / "wechat_notice_demo.py"
WECHAT_FILE_DEMO = Path(__file__).resolve().parent / "wechat_file_demo.py"
WXRSS_SOURCE_MAP = {
    "360漏洞研究院": "22c9636bddf9a569199f00ef8737f277",
    "奇安信 CERT": "bac73cb7b9d619d554d6fa92183619cf",
    "微步在线研究响应中心": "0ec965db2338ab2db51b01eb75a14ef6",
    "长亭安全应急响应中心": "af152e893d94cd00a5ad409c3c757391",
}

def load_processed_values(file_path):
    if not os.path.exists(file_path):
        return set()
    with open(file_path, 'r') as f:
        return {line.strip() for line in f if line.strip()}

def append_processed_values(file_path, values):
    if not values:
        return
    with open(file_path, 'a') as f:
        for value in values:
            f.write(f"{value}\n")

def load_processed_shas():
    return load_processed_values(github_sha)


def load_json_state(file_path):
    # Load a small JSON state file and fall back to an empty dictionary when absent.
    if not os.path.exists(file_path):
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json_state(file_path, payload):
    # Persist a small JSON state file used by RSS-style WeChat publisher monitoring.
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def get_repo_sha_file(repo):
    # Return the per-repo SHA state file path used by repo_list monitoring.
    safe_name = repo.replace("/", "__")
    os.makedirs(github_repo_sha_dir, exist_ok=True)
    return os.path.join(github_repo_sha_dir, f"{safe_name}.txt")


def load_repo_processed_shas(repo):
    # Load processed commit SHAs for one monitored repository.
    return load_processed_values(get_repo_sha_file(repo))


def normalize_wechat_source_name(value):
    # Normalize configured WeChat source names for matching and deduplication.
    return re.sub(r"\s+", "", str(value or "")).strip().lower()


def canonicalize_wechat_link(link):
    # Normalize WeChat article links so cross-source duplicates can be recognized.
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


def build_wechat_article_key(publisher, title):
    # Build a stable cross-source dedupe key for one monitored WeChat article.
    normalized_publisher = normalize_wechat_source_name(publisher)
    normalized_title = re.sub(r"\s+", " ", str(title or "")).strip()
    return f"{normalized_publisher}::{normalized_title}"


def load_processed_wechat_article_keys():
    # Load processed WeChat article markers and expand historical URLs into canonical link keys.
    values = load_processed_values(wechat_articles_state)
    expanded_values = set(values)
    for value in list(values):
        canonical_link = canonicalize_wechat_link(value)
        if canonical_link:
            expanded_values.add(canonical_link)
    return expanded_values


def is_processed_wechat_article(processed_values, item):
    # Check whether the same article was already seen from any source.
    candidates = {
        item.get("key", ""),
        str(item.get("link", "")).strip(),
        canonicalize_wechat_link(item.get("link", "")),
    }
    return any(candidate and candidate in processed_values for candidate in candidates)


def mark_wechat_article_processed(processed_values, item):
    # Persist all useful dedupe keys so the same article is not pushed twice across sources.
    candidates = []
    for value in [
        item.get("key", ""),
        str(item.get("link", "")).strip(),
        canonicalize_wechat_link(item.get("link", "")),
    ]:
        if value and value not in processed_values:
            processed_values.add(value)
            candidates.append(value)
    append_processed_values(wechat_articles_state, candidates)


def is_notice_like_wechat_article(publisher, title):
    # Decide whether a monitored WeChat article is a vulnerability notice worth generating into MSS documents.
    normalized_publisher = normalize_wechat_source_name(publisher)
    if normalized_publisher not in {
        normalize_wechat_source_name("360漏洞研究院"),
        normalize_wechat_source_name("奇安信 CERT"),
    }:
        return False
    lowered_title = str(title or "").lower()
    positive_keywords = [
        "漏洞",
        "cve-",
        "通告",
        "风险通告",
        "已复现",
        "在野利用",
        "代码执行",
        "命令执行",
        "提权",
        "沙箱逃逸",
        "认证绕过",
        "sql注入",
        "信息泄露",
        "文件上传",
    ]
    negative_keywords = [
        "周报",
        "日报",
        "月报",
        "速览",
        "动态总结",
        "情报",
        "资讯",
        "直播",
        "课程",
        "产品",
        "招聘",
        "活动",
        "案例",
    ]
    if any(keyword in lowered_title for keyword in negative_keywords):
        return False
    return any(keyword in lowered_title for keyword in positive_keywords)


def is_candidate_wechat_notice_title(title):
    # Decide whether one external-source title is worth resolving through wechatmp2markdown.
    lowered_title = str(title or "").lower()
    positive_keywords = [
        "漏洞",
        "cve-",
        "通告",
        "风险通告",
        "已复现",
        "在野利用",
        "在野漏洞预警",
        "代码执行",
        "命令执行",
        "提权",
        "沙箱逃逸",
        "认证绕过",
        "sql注入",
        "信息泄露",
        "文件上传",
    ]
    negative_keywords = [
        "周报",
        "日报",
        "月报",
        "速览",
        "动态总结",
        "情报",
        "资讯",
        "直播",
        "课程",
        "产品",
        "招聘",
        "活动",
        "案例",
    ]
    if any(keyword in lowered_title for keyword in negative_keywords):
        return False
    return any(keyword in lowered_title for keyword in positive_keywords)


def get_wechatmp2markdown_executable():
    # Return the local wechatmp2markdown binary path used for publisher resolution.
    system_name = platform.system().lower()
    if "darwin" in system_name:
        candidate = ARTICLE_DIR / "wechatmp2markdown-v1.1.11_osx_amd64"
    else:
        candidate = ARTICLE_DIR / "wechatmp2markdown-v1.1.11_linux_amd64"
    if not candidate.exists():
        raise FileNotFoundError(f"未找到 wechatmp2markdown 可执行文件: {candidate}")
    os.chmod(candidate, 0o755)
    return str(candidate)


def resolve_wechat_article_publisher(url, configured_sources):
    # Resolve one WeChat article publisher by converting the article to markdown and reading the header.
    executable = get_wechatmp2markdown_executable()
    normalized_source_map = {
        normalize_wechat_source_name(source_name): source_name for source_name in configured_sources
    }
    temp_directory = tempfile.mkdtemp(prefix="wechat_source_resolve_")
    start_time = time.monotonic()
    logging.info(f"公众号来源识别开始: {url}")
    try:
        subprocess.check_output(
            [executable, url, temp_directory, "--image=url"],
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        for root, _, files in os.walk(temp_directory):
            for file_name in files:
                if not file_name.endswith(".md"):
                    continue
                markdown_text = Path(root, file_name).read_text(encoding="utf-8", errors="ignore")
                head_text = "\n".join(markdown_text.splitlines()[:20])
                normalized_head = normalize_wechat_source_name(head_text)
                for normalized_source, source_name in normalized_source_map.items():
                    if normalized_source and normalized_source in normalized_head:
                        elapsed = time.monotonic() - start_time
                        logging.info(f"公众号来源识别完成: {url} -> {source_name}, 耗时 {elapsed:.2f}s")
                        return source_name
    except Exception as exc:
        elapsed = time.monotonic() - start_time
        logging.warning(f"公众号来源识别失败: {url} - {exc}, 耗时 {elapsed:.2f}s")
    finally:
        shutil.rmtree(temp_directory, ignore_errors=True)
    elapsed = time.monotonic() - start_time
    logging.info(f"公众号来源识别未命中配置公众号: {url}, 耗时 {elapsed:.2f}s")
    return ""


def run_wechat_notice_generation(article_url):
    # Run the standalone article notice generator and return the generated document paths.
    command = [
        "python3",
        str(ARTICLE_NOTICE_SCRIPT),
        article_url,
        "--debug-json",
        "--compact",
    ]
    completed = subprocess.run(
        command,
        cwd=str(ARTICLE_DIR),
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
    notice_path = payload.get("notice", "")
    regulator_notice_path = payload.get("regulator_notice", "")
    if not notice_path or not regulator_notice_path:
        raise RuntimeError(f"文章生成脚本未返回完整文档路径: {payload}")
    return payload


def send_wechat_file_via_demo(file_path):
    # Send one generated document to WeCom through the existing file-demo wrapper.
    command = [
        "python3",
        str(WECHAT_FILE_DEMO),
        str(file_path),
        "--compact",
    ]
    completed = subprocess.run(
        command,
        cwd=str(Path(__file__).resolve().parent),
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


def cleanup_generated_notice_files(generation_payload):
    # Delete generated docx files after successful delivery and keep JSON artifacts only.
    notice_path = Path(generation_payload.get("notice", ""))
    regulator_notice_path = Path(generation_payload.get("regulator_notice", ""))
    for path in (notice_path, regulator_notice_path):
        if path and path.exists():
            path.unlink()
    parent_dir = notice_path.parent if notice_path else None
    if parent_dir and parent_dir.exists():
        remaining_files = [item for item in parent_dir.iterdir() if item.is_file()]
        if not remaining_files:
            parent_dir.rmdir()
            date_dir = parent_dir.parent
            if date_dir.exists() and not any(date_dir.iterdir()):
                date_dir.rmdir()


def generate_and_push_wechat_notice_documents(article):
    # Generate the two MSS notice documents for one monitored WeChat article and send them to WeCom.
    publisher = article.get("publisher", "未知公众号")
    title = article.get("title", "")
    link = article.get("link", "")
    if not link:
        raise ValueError("缺少公众号文章链接，无法生成通告")
    generation_payload = run_wechat_notice_generation(link)
    notice_path = generation_payload["notice"]
    regulator_notice_path = generation_payload["regulator_notice"]
    send_wechat_file_via_demo(notice_path)
    send_wechat_file_via_demo(regulator_notice_path)
    cleanup_generated_notice_files(generation_payload)
    logging.info(f"企微推送生成通告成功：{publisher} - {title}")

github_headers = {
    'Authorization': "token {}".format(github_token)
}


def checkEnvData():
    if not github_token:
        logging.error("github_token 获取失败")
        exit(0)
    elif not msg_push.tg_token:  
        logging.error("TG_token获取失败")
        exit(0)
    elif not msg_push.wechat_token:  
        logging.error("wechat_token获取失败")
        exit(0)
    elif not msg_push.google_sheet_token:
        logging.error("google_sheet_token获取失败")
        exit(0)
    elif not msg_push.tg_chat_id:
        logging.error("tg_chat_id获取失败")
        exit(0)
    else:
        logging.info("环境变量加载成功")


def init():
    logging.basicConfig(level=logging.INFO)
    logging.info("init application")
    checkEnvData()
    logging.info("start send test msg")
    return

def getRSSNews():
    rss_config = utils.load.json_data_load("./RSSs/rss_config.json")
    for key, config in rss_config.items():
        url = config.get("url")
        file_name = config.get("file")
        if url and file_name:
            parse_rss_feed(url,file_name)


def monitor_wechat_publishers():
    # Monitor configured WeChat publishers through fixed wxrss_static RSS feeds and push new articles to WeCom.
    configured_sources = [item for item in wechat_sources if str(item).strip()]
    if not configured_sources:
        logging.info("未配置微信公众号监控源，跳过")
        return

    try:
        articles = collect_new_wechat_articles(configured_sources)
    except Exception as exc:
        logging.error(f"微信公众号 RSS 监控失败: {exc}")
        return

    if not articles:
        logging.info("微信公众号监控未发现新文章")
        return

    for article in articles:
        publisher = article.get("publisher", "未知公众号")
        title = article.get("title", "")
        link = article.get("link", "")
        relative_path = article.get("relative_path", "")
        msg = f"公众号新文章推送:\r\n公众号：{publisher}\r\n标题：{title}\r\n链接：{link or relative_path}"
        msg_push.wechat_push(msg)
        logging.info(f"企微推送公众号文章：{publisher} - {title}")
        if is_notice_like_wechat_article(publisher, title):
            try:
                generate_and_push_wechat_notice_documents(article)
            except Exception as exc:
                logging.error(f"公众号漏洞通告生成/推送失败: {publisher} - {title} - {exc}")


def fetch_wxrss_items(source_name, folder_id):
    # Fetch one monitored publisher RSS feed from wxrss_static and return parsed items.
    rss_url = f"{WXRSS_RAW_BASE}/{folder_id}/rss.xml"
    start_time = time.monotonic()
    logging.info(f"开始拉取公众号源 wxrss_static: {source_name}, folder={folder_id}")
    response = requests.get(rss_url, timeout=20)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    channel = root.find("channel")
    if channel is None:
        return []
    channel_title = (channel.findtext("title") or "").strip()
    normalized_expected = normalize_wechat_source_name(source_name)
    normalized_actual = normalize_wechat_source_name(channel_title)
    if normalized_actual != normalized_expected:
        raise ValueError(
            f"公众号名称不匹配: expected={source_name}, actual={channel_title}, folder={folder_id}"
        )

    items = []
    for item in channel.findall("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        if not title:
            continue
        items.append(
            {
                "source": "wxrss_static",
                "publisher": source_name,
                "title": title,
                "link": link,
                "pub_date": pub_date,
                "relative_path": f"{folder_id}/rss.xml",
                "key": build_wechat_article_key(source_name, title),
            }
        )
    elapsed = time.monotonic() - start_time
    logging.info(f"完成拉取公众号源 wxrss_static: {source_name}, items={len(items)}, 耗时 {elapsed:.2f}s")
    return items


def fetch_doonsec_items(configured_sources):
    # Fetch monitored publisher articles from Doonsec's WeChat RSS feed.
    start_time = time.monotonic()
    logging.info("开始拉取公众号源 doonsec")
    normalized_sources = {
        normalize_wechat_source_name(source_name): source_name for source_name in configured_sources
    }
    feed = feedparser.parse(DOONSEC_WECHAT_RSS)
    items = []
    for entry in getattr(feed, "entries", []):
        publisher = normalized_sources.get(normalize_wechat_source_name(getattr(entry, "author", "")))
        if not publisher:
            continue
        title = str(getattr(entry, "title", "")).strip()
        link = str(getattr(entry, "link", "")).strip()
        pub_date = str(getattr(entry, "published", "") or getattr(entry, "pubDate", "")).strip()
        if not title or not link.startswith("https://mp.weixin.qq.com/"):
            continue
        items.append(
            {
                "source": "doonsec",
                "publisher": publisher,
                "title": title,
                "link": link,
                "pub_date": pub_date,
                "relative_path": "doonsec:rss.xml",
                "key": build_wechat_article_key(publisher, title),
            }
        )
    elapsed = time.monotonic() - start_time
    logging.info(f"完成拉取公众号源 doonsec, items={len(items)}, 耗时 {elapsed:.2f}s")
    return items


def parse_picker_markdown_items(markdown_text, configured_sources, source_name, relative_path):
    # Parse publisher-grouped WeChat entries from a picker daily markdown file and resolve unmatched notice links.
    normalized_sources = {
        normalize_wechat_source_name(item): item for item in configured_sources
    }
    items = []
    current_publisher = ""
    for raw_line in markdown_text.splitlines():
        section_match = re.match(r"^-\s+(.+?)\s*$", raw_line)
        if section_match and "[" not in raw_line:
            current_publisher = section_match.group(1).strip()
            continue
        item_match = re.match(r"^\s*-\s+\[\s*\]\s+\[(.+?)\]\((https://mp\.weixin\.qq\.com/[^)]+)\)", raw_line)
        if not item_match or not current_publisher:
            continue
        title = item_match.group(1).strip()
        link = item_match.group(2).strip()
        normalized_publisher = normalize_wechat_source_name(current_publisher)
        publisher = normalized_sources.get(normalized_publisher, "")
        if not publisher and is_candidate_wechat_notice_title(title):
            publisher = resolve_wechat_article_publisher(link, configured_sources)
        if not publisher:
            continue
        items.append(
            {
                "source": source_name,
                "publisher": publisher,
                "title": title,
                "link": link,
                "pub_date": "",
                "relative_path": relative_path,
                "key": build_wechat_article_key(publisher, title),
            }
        )
    return items


def fetch_picker_items(configured_sources, source_name, base_url):
    # Fetch one daily picker markdown and extract entries that belong to configured publishers.
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")
    url = base_url.format(year=current_date[:4], date=current_date)
    start_time = time.monotonic()
    logging.info(f"开始拉取公众号源 {source_name}: {url}")
    response = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
    if response.status_code == 404:
        elapsed = time.monotonic() - start_time
        logging.info(f"公众号源 {source_name} 当日无数据: {url}, 耗时 {elapsed:.2f}s")
        return []
    response.raise_for_status()
    items = parse_picker_markdown_items(
        response.text,
        configured_sources,
        source_name,
        f"{source_name}:{current_date}",
    )
    elapsed = time.monotonic() - start_time
    logging.info(f"完成拉取公众号源 {source_name}, items={len(items)}, 耗时 {elapsed:.2f}s")
    return items


def process_wechat_source_items(source_state, processed_article_keys, articles, initialized_sources, source_id, source_name, items):
    # Merge one source stream into the global article queue with per-source state and cross-source dedupe.
    if not items:
        logging.info(f"公众号源无可处理条目: {source_id}:{source_name}")
        return
    state_key = f"{source_id}:{source_name}"
    latest_key = items[0]["key"]
    previous_key = source_state.get(state_key)
    if source_id == "wxrss_static" and not previous_key:
        previous_key = source_state.get(source_name)
    logging.info(
        f"处理公众号源状态: {state_key}, previous={previous_key or 'EMPTY'}, latest={latest_key}, items={len(items)}"
    )
    if not previous_key:
        source_state[state_key] = latest_key
        initialized_sources.append(state_key)
        logging.info(f"公众号源首次初始化: {state_key}, latest={latest_key}")
        return

    pending = []
    for item in items:
        item_key = item["key"]
        if item_key == previous_key:
            break
        if is_processed_wechat_article(processed_article_keys, item):
            continue
        pending.append(item)
    logging.info(f"公众号源待推送文章数: {state_key}, pending={len(pending)}")

    if len(pending) > WECHAT_MAX_PENDING_PER_SOURCE:
        logging.info(
            f"公众号源积压过多，跳过历史文章并推进边界: {state_key}, pending={len(pending)}"
        )
        source_state[state_key] = latest_key
        return

    for item in reversed(pending):
        mark_wechat_article_processed(processed_article_keys, item)
        articles.append(item)
    source_state[state_key] = latest_key


def collect_new_wechat_articles(configured_sources):
    # Read configured publisher feeds from multiple sources and return only newly published articles.
    start_time = time.monotonic()
    logging.info(f"开始汇总公众号文章，configured_sources={','.join(configured_sources)}")
    processed_article_keys = load_processed_wechat_article_keys()
    source_state = load_json_state(wechat_source_state)
    articles = []
    initialized_sources = []
    for source_name in configured_sources:
        folder_id = WXRSS_SOURCE_MAP.get(source_name)
        if not folder_id:
            logging.warning(f"未找到公众号映射，跳过: {source_name}")
            continue
        process_wechat_source_items(
            source_state,
            processed_article_keys,
            articles,
            initialized_sources,
            "wxrss_static",
            source_name,
            fetch_wxrss_items(source_name, folder_id),
        )

    for source_id, fetcher in [
        ("doonsec", lambda: fetch_doonsec_items(configured_sources)),
        ("bruce_picker", lambda: fetch_picker_items(configured_sources, "bruce_picker", BRUCE_PICKER_DAILY)),
        ("chainreactors_picker", lambda: fetch_picker_items(configured_sources, "chainreactors_picker", CHAINREACTORS_PICKER_DAILY)),
    ]:
        try:
            fetched_items = fetcher()
        except Exception as exc:
            logging.warning(f"公众号补充源拉取失败: {source_id} - {exc}")
            continue
        grouped_items = {}
        for item in fetched_items:
            grouped_items.setdefault(item["publisher"], []).append(item)
        for source_name, items in grouped_items.items():
            process_wechat_source_items(
                source_state,
                processed_article_keys,
                articles,
                initialized_sources,
                source_id,
                source_name,
                items,
            )

    save_json_state(wechat_source_state, source_state)
    elapsed = time.monotonic() - start_time
    logging.info(f"公众号状态已保存，new_articles={len(articles)}, initialized={len(initialized_sources)}, 耗时 {elapsed:.2f}s")
    if initialized_sources:
        logging.info(f"首次初始化公众号源状态，已记录最新文章并跳过历史: {', '.join(initialized_sources)}")
    return articles

def extract_cve_ids(text):
    """从文本中提取所有CVE编号"""
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    return re.findall(cve_pattern, text, re.IGNORECASE)

def check_cve_in_poc_history(cve_id):
    """检查CVE是否在历史PoC记录中，返回PoC链接列表"""
    try:
        table_content = msg_push.get_google_sheet("CVE")
        if not table_content or len(table_content) < 2:
            return []
        # 表头：时间、关键词、项目名称、项目地址、项目描述
        headers = table_content[0]
        keyword_idx = headers.index("关键词") if "关键词" in headers else 1
        url_idx = headers.index("项目地址") if "项目地址" in headers else 3
        
        poc_links = []
        for row in table_content[1:]:
            if len(row) > max(keyword_idx, url_idx):
                keyword = row[keyword_idx].upper() if row[keyword_idx] else ""
                if cve_id.upper() in keyword:
                    poc_links.append(row[url_idx])
        return poc_links
    except Exception as e:
        logging.error(f"查询CVE历史PoC失败: {e}")
        return []


def clean_markdown_text(text):
    # Strip the most common markdown markers so advisory details read cleanly in push messages.
    cleaned = str(text or "")
    cleaned = re.sub(r"`([^`]*)`", r"\1", cleaned)
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
    cleaned = re.sub(r"(?m)^\s{0,3}#{1,6}\s*", "", cleaned)
    cleaned = re.sub(r"(?m)^\s*[-*]\s*", "", cleaned)
    cleaned = re.sub(r"\r", "", cleaned)
    cleaned = re.sub(r"\n{2,}", "\n", cleaned)
    return cleaned.strip()


def truncate_text(text, limit=220):
    # Keep push text short enough for chat notifications without dropping the main point.
    normalized = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3].rstrip() + "..."


def safe_translate_text(text):
    # Translate a short advisory snippet to Chinese and fall back to the original text on failure.
    normalized = str(text or "").strip()
    if not normalized:
        return ""
    if not utils.load.baidu_appid or not utils.load.baidu_appkey:
        return normalized
    try:
        return utils.load.baidu_api(normalized)
    except Exception as exc:
        logging.warning(f"百度翻译失败，使用原文回退: {exc}")
        return normalized


def extract_impact_excerpt(details):
    # Extract the impact section from advisory details, or fall back to the opening paragraphs.
    markdown = str(details or "").strip()
    if not markdown:
        return ""
    sections = re.split(r"(?m)^##\s+", markdown)
    for section in sections:
        section = section.strip()
        if not section:
            continue
        lines = section.splitlines()
        heading = lines[0].strip().lower()
        body = "\n".join(lines[1:]).strip()
        if heading == "impact" and body:
            return clean_markdown_text(body)
    return clean_markdown_text(markdown)


def extract_affected_versions(data):
    # Summarize affected version ranges so the alert includes a concrete upgrade boundary.
    seen = []
    for affected in data.get('affected', []) or []:
        package = (affected.get('package') or {}).get('name') or "unknown"
        for item_range in affected.get('ranges', []) or []:
            introduced = ""
            fixed = ""
            for event in item_range.get('events', []) or []:
                if event.get('introduced') is not None:
                    introduced = str(event.get('introduced'))
                if event.get('fixed') is not None:
                    fixed = str(event.get('fixed'))
            if fixed and introduced and introduced != "0":
                version_text = f"{package} {introduced} - < {fixed}"
            elif fixed:
                version_text = f"{package} < {fixed}"
            elif introduced and introduced != "0":
                version_text = f"{package} >= {introduced}"
            else:
                version_text = package
            if version_text not in seen:
                seen.append(version_text)
    return "；".join(seen[:4]) if seen else "未知"


def fetch_cvss_score(cve_id):
    # Query NVD for a numeric CVSS base score and fall back to unknown when the API has no metric yet.
    normalized_cve = str(cve_id or "").strip().upper()
    if not normalized_cve.startswith("CVE-"):
        return "未知"
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": normalized_cve},
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logging.warning(f"NVD CVSS 查询失败 {normalized_cve}: {exc}")
        return "未知"

    vulnerabilities = payload.get("vulnerabilities", []) or []
    if not vulnerabilities:
        return "未知"
    metrics = ((vulnerabilities[0].get("cve") or {}).get("metrics") or {})
    metric_order = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    for metric_key in metric_order:
        for metric in metrics.get(metric_key, []) or []:
            cvss_data = metric.get("cvssData") or {}
            base_score = cvss_data.get("baseScore")
            if base_score is not None:
                return str(base_score)
    return "未知"


def lookup_github_poc_status(cve_id):
    # Reuse the GitHub PoC search pipeline and return whether the matched CVE already has PoC clues.
    normalized_cve = str(cve_id or "").strip().upper()
    if not normalized_cve.startswith("CVE-"):
        return "未知", []
    try:
        result = build_cve_response(normalized_cve)
    except Exception as exc:
        logging.warning(f"GitHub PoC 查询失败 {normalized_cve}: {exc}")
        return "未知", []
    repo_items = result.get("repo_search", {}).get("top_repositories", []) or []
    repo_links = [item.get("html_url") for item in repo_items if item.get("html_url")]
    advisory = (result.get("advisory") or {}).get("selected") or {}
    reference_links = [
        item.get("url")
        for item in advisory.get("likely_poc_references", []) or []
        if item.get("url")
    ]
    has_poc = bool(repo_links or reference_links or advisory.get("description_mentions_poc"))
    links = (repo_links + reference_links)[:2]
    return ("是" if has_poc else "否"), links


def build_github_advisory_message(data, matched_object, severity, advisory_url):
    # Build a concise advisory push message with summary, CVSS score, and PoC presence.
    aliases = data.get('aliases', []) or []
    cve_id = next((alias for alias in aliases if alias.upper().startswith("CVE-")), "")
    summary_text = safe_translate_text(clean_markdown_text(data.get('summary', '') or ''))
    cvss_text = fetch_cvss_score(cve_id)
    poc_status, poc_links = lookup_github_poc_status(cve_id)

    lines = [
        f"编号：{cve_id}",
        f"组件：{matched_object}",
        f"严重性：{severity}",
        f"CVSS：{cvss_text}",
    ]
    if summary_text:
        lines.append(f"概要：{truncate_text(summary_text, 160)}")
    if poc_links:
        lines.append(f"GitHub PoC：{' | '.join(poc_links)}")
    else:
        lines.append(f"GitHub PoC：{poc_status}")
    lines.append(f"链接：{advisory_url}")
    return "\r\n".join(lines)

def parse_rss_feed(feed_url,file):
    # 解析RSS feed
    try:
        response = requests.get(feed_url,timeout=20)
        response.raise_for_status()
    except requests.exceptions.SSLError as ssl_err:
        logging.error(f"SSL 错误：无法连接 {feed_url}，跳过该条目。错误信息：{ssl_err}")
        return  # 发生 SSL 错误时跳过当前循环
    except requests.exceptions.RequestException as req_err:
        logging.error(f"请求错误：{feed_url}，错误信息：{req_err}")
        return  # 发生请求错误时跳过当前循环
    except Exception as e:
        logging.error(f"未知错误：{feed_url}，错误信息：{e}")
        return  # 发生其他类型的错误时跳过
    response.encoding = 'utf-8'
    feed_content = response.text
    # 解析RSS feed内容
    feed = feedparser.parse(feed_content)
    if feed.bozo == 1:
        if not feed.entries:
            logging.warning(f"{file} 解析RSS feed时发生错误且无有效条目: {feed.bozo_exception}")
            return
        logging.warning(f"{file} 解析RSS feed时发生错误，但存在可用条目: {feed.bozo_exception}")
    all_entries = utils.load.json_data_load(f"./RSSs/{file}")
    existing_titles = {entry['link'] for entry in all_entries}
    # 定义一个标志，标记是否输出了新增条目
    new_entries_found = False
    for entry in feed.entries:
        entry_link = getattr(entry, 'link', '')
        entry_title = getattr(entry, 'title', '')
        entry_published = getattr(entry, 'published', '')
        entry_content = str(getattr(entry, 'content', '') or '')

        if not entry_link or entry_link in existing_titles:
            continue

        if file == "google.json":
            if 'cve' not in entry_content.lower():
                all_entries.append({
                    'title': entry_title,
                    'link': entry_link,
                    'published': entry_published
                })
                new_entries_found = True
                continue

        # 输出新增条目
        new_entries_found = True
        all_content_have_cve = True
        if file == "vulncheck.json" or file == "securityonline.json" or file == "picus.json" or file == "rapid7.json" or file == "thehackersnews.json":
            if "cve" not in entry_title.lower() and "vulnerabili" not in entry_title.lower():
                all_content_have_cve = False  # 如果发现某个 content 没有 "CVE"，标记为 False
        if file == "zerodayinitiative.json":
            if ("cve" not in entry_title.lower() and "vulnerabili" not in entry_title.lower()) and "Security Update Review" not in entry_title:
                all_content_have_cve = False  # 如果发现某个 content 没有 "CVE"，标记为 False
        if file == "paloalto.json":
            if "medium" in entry_title.lower() or "low" in entry_title.lower():
                all_content_have_cve = False  # 如果发现某个 content 没有 "CVE"，标记为 False
        if file == "thehackerwire.json":
            if "cve" not in entry.get('summary', '').lower():
                all_content_have_cve = False  # 如果发现某个 content 没有 "CVE"，标记为 False
        if file == "gbhackers.json":
            categories = []
            if 'tags' in entry:
                categories = [tag.term for tag in entry.tags]
            elif 'category' in entry:
                categories = entry.category if isinstance(entry.category, list) else [entry.category]
            if not any(cat in ["Vulnerability", "Vulnerabilities"] for cat in categories):
                all_content_have_cve = False

        all_entries.append({
                'title': entry_title,
                'link': entry_link,
                'published': entry_published
            })

        if not all_content_have_cve:
            continue

        logging.info(f"标题: {entry_title}  链接: {entry_link}")
        logging.info("-" * 40)
        # 将新增条目添加到新条目列表
        if all_content_have_cve:
            # 检查是否存在历史PoC
            poc_prefix = ""
            cve_ids = extract_cve_ids(entry_title)
            for cve_id in cve_ids:
                poc_links = check_cve_in_poc_history(cve_id)
                if poc_links:
                    poc_prefix = f"该漏洞疑似存在poc批量：「{poc_links[0]}」\r\r"
                    logging.info(f"发现历史PoC: {cve_id} -> {poc_links[0]}")
                    break  # 找到一个就够了
            
            msg = f"{poc_prefix}标题：{entry_title}\r链接：{entry_link}\r发布时间：{entry_published}"
            logging.info(f"推送到google sheet：{entry_title}  "+entry_link)
            msg_push.wechat_push(msg)
            msg_push.send_google_sheet_githubVul("Emergency Vulnerability","RSS",entry_title,"",entry_link,"")
    # 如果有新增条目，则更新文件
    if new_entries_found:
        utils.load.json_data_save(f"./RSSs/{file}",all_entries)
    else:
        logging.info(f"{file}未更新新漏洞")

def get_github_raw_links(github_url):
    # 解析地址，提取 owner 和 repo
    parts = github_url.strip('/').split('/')
    owner, repo = parts[-2], parts[-1]
    
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/"
    raw_links = []
    
    try:
        response = requests.get(api_url, headers=github_headers)
        if response.status_code != 200:
            logging.error(f"提取Raw地址请求失败，状态码：{response.status_code}")

            return "响应码错误"  # 请求失败或无权限
        
        for item in response.json():
            if item['type'] == 'file' and item['name'].endswith(('.py', '.yaml', '.yml')):
                raw_links.append(item['download_url'])
        
        if isinstance(raw_links, list):
            return '\n'.join(raw_links) if raw_links else "无脚本文件"
        return str(raw_links)
    except Exception as e:
        logging.error(f"提取Raw地址请求失败，错误信息：{e}")
        return "网络错误异常"  # 网络错误或其他异常
   
def getKeywordNews(keyword):
    cleanKeywords=set(CleanKeywords)
    today_keyword_info_tmp=[]
    try:
        # 使用上海时区获取今天的日期
        import pytz
        shanghai_tz = pytz.timezone('Asia/Shanghai')
        today_date = datetime.datetime.now(shanghai_tz).date()
        
        # 在查询中指定创建日期，按更新时间排序
        query = f"{keyword}+created:{today_date}"
        api = f"https://api.github.com/search/repositories?q={query}&sort=updated"
        logging.info(f"搜索: {keyword}, 日期: {today_date}")
        
        json_str = requests.get(api, headers=github_headers, timeout=10).json()
        n=20 if len(json_str.get('items', []))>20 else len(json_str.get('items', []))
        
        for i in range(0, n):
            keyword_url = json_str['items'][i]['html_url']
            try:
                keyword_name = json_str['items'][i]['name']
                description = json_str['items'][i]['description']
                created_at_tmp = json_str['items'][i]['created_at']
                created_at = re.findall(r'\d{4}-\d{2}-\d{2}', created_at_tmp)[0]
                
                if keyword_name not in cleanKeywords:
                    msg_push.send_google_sheet("CVE",keyword,keyword_name,keyword_url,description)
                    if "CVE" in keyword:
                        raw_links = get_github_raw_links(keyword_url)
                        msg_push.send_google_raw("raw",keyword_url,raw_links)
                    today_keyword_info_tmp.append({"keyword_name": keyword_name, "keyword_url": keyword_url, "pushed_at": created_at,"description":description})

                    logging.info("[+] keyword: {} \n 项目名称：{} \n项目地址：{}\n创建时间：{}\n描述：{}".format(keyword, keyword_name,keyword_url,created_at,description))
                else:
                    logging.info("[-] keyword: {} ,{}已经收录，跳过".format(keyword, keyword_name))
            except Exception as e:
                pass
    except Exception as e:
        logging.error("Error occurred: %s, github链接不通", e) 
    return today_keyword_info_tmp
    
def getCVE_PoCs():
    #通过关键词检索PoC
    clean_add = []
    pushdata=list()
    for keyword in keywords:
        templist=getKeywordNews(keyword)
        for tempdata in templist:
            pushdata.append(tempdata)
            clean_add.append(tempdata.get("keyword_name"))
    msg_push.keyword_msg(pushdata)
    if clean_add:
        utils.load.flash_clean_list(clean_add)

def check_yesterday_hot_repos():
    """检查最近3天创建的热门项目（star数>=5），包括今天、昨天、前天"""
    import pytz
    shanghai_tz = pytz.timezone('Asia/Shanghai')
    today_date = datetime.datetime.now(shanghai_tz).date()
    three_days_ago = today_date - datetime.timedelta(days=2)  # 前天
    
    # 热门项目记录文件
    hot_repos_file = "./utils/hot_repos.txt"
    
    # 加载已推送的项目列表
    if os.path.exists(hot_repos_file):
        with open(hot_repos_file, 'r') as f:
            pushed_repos = set(line.strip() for line in f if line.strip())
    else:
        pushed_repos = set()
    
    logging.info(f"检查最近3天（{three_days_ago} 至 {today_date}）创建的热门项目")
    
    new_hot_repos = []
    for keyword in keywords:
        try:
            # 搜索最近3天创建的项目（前天、昨天、今天），按star数排序
            query = f"{keyword}+created:{three_days_ago}..{today_date}"
            api = f"https://api.github.com/search/repositories?q={query}&sort=stars"
            json_str = requests.get(api, headers=github_headers, timeout=10).json()
            
            if 'items' not in json_str:
                continue
                
            for item in json_str['items']:
                stars = item.get('stargazers_count', 0)
                if stars >= 5:
                    name = item['name']
                    url = item['html_url']
                    
                    # 检查是否已推送过
                    if url not in pushed_repos:
                        msg = f"{url}\n该poc单日热度较高，近期star数为「{stars}」"
                        logging.info(f"发现热门项目: {name}, stars: {stars}")
                        msg_push.wechat_push(msg)
                        new_hot_repos.append(url)
                    else:
                        logging.info(f"项目 {name} 已推送过，跳过")
                    
        except Exception as e:
            logging.error(f"检查昨天热门项目失败: {keyword}, 错误: {e}")
            continue
    
    # 保存新推送的项目
    if new_hot_repos:
        with open(hot_repos_file, 'a') as f:
            for url in new_hot_repos:
                f.write(f"{url}\n")

def getCISANews():
    with open('./utils/CISA.txt', 'r') as file:
        txt_content = file.read().splitlines()
    url = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'
    # 读取 CSV 内容
    try:
        response = requests.get(url)
    except Exception as e:
        # 捕获其他可能的异常
        logging.info(f"An unexpected error occurred: {e}")
        return
    response.raise_for_status()  # 检查请求是否成功
    data = response.text  # 获取 CSV 文件内容
    reader = csv.DictReader(data.splitlines())
    msg = ""
    new_cve_list = []
    for row in reader:
        cve = row['cveID']  # 假设 'cveID' 是 CSV 中的列名
        if cve not in txt_content:
            name = row['vulnerabilityName'] + "(" + cve + ")"
            name_cn = utils.load.baidu_api(name)
            shortDescription = row['shortDescription']
            knownRansomwareCampaignUse = row['knownRansomwareCampaignUse']
            shortDescription_cn = utils.load.baidu_api(shortDescription)
            notes = row['notes']
            info = f"名称：{name_cn}\r\n描述：{shortDescription_cn}\r\n是否被勒索利用：{knownRansomwareCampaignUse}\r\n链接：{notes}"
            if not msg:
                msg = "美国网络安全局漏洞推送：\r\n" + info
            else:
                msg += "\r\n\r\n" + info
            new_cve_list.append(cve)
    
    if new_cve_list:
        logging.info("企微推送CISA漏洞更新："  + ", ".join(new_cve_list))
        msg_push.wechat_push(msg)
        msg_push.tg_push(msg)
        with open("./utils/CISA.txt", 'a') as file:
            for cve in new_cve_list:
                file.write(f"{cve}\n")
    else:
        logging.info("CISA未更新漏洞")

def save_file_locally(url, filename, processed_advisory_ids=None):
    try:
        response = requests.get(url, headers=github_headers, timeout=20)
    except Exception as e:
        logging.info(f"An unexpected error occurred: {e}")
        return False
    if response.status_code == 200:
        data = response.json()
        advisory_key = extract_advisory_key(data, filename)
        if processed_advisory_ids is not None and advisory_key in processed_advisory_ids:
            logging.info(f"漏洞 {advisory_key} 已推送过，跳过")
            return False
        match_result = match_known_object(data, known_object)
        if match_result["matched"]:
            item = match_result["matched_object"]
            severity = match_result.get("severity", "UNKNOWN")
            aliases = data.get('aliases', []) or []
            cve_id = next((alias for alias in aliases if alias.upper().startswith("CVE-")), "")
            if not cve_id:
                logging.info(f"重点组件漏洞缺少 CVE 编号，跳过推送: {data.get('id', '') or filename}")
                return False
            url = f"https://github.com/advisories/{data.get('id', '')}"
            msg = build_github_advisory_message(data, item, severity, url)
            logging.info(f"企微推送：{advisory_key}  {url}")
            msg_push.wechat_push(msg)
            msg_push.send_google_sheet_githubVul("Emergency Vulnerability","github",item,advisory_key,url,msg)
            msg_push.tg_push(msg)
            if processed_advisory_ids is not None:
                processed_advisory_ids.add(advisory_key)
                append_processed_values(github_advisory_ids, [advisory_key])
            return True
    else:
        logging.info(f"Failed to read {filename}: {response.status_code}")
    return False


def getGithubVun():
    url = "https://api.github.com/repos/github/advisory-database/commits"
    try:
        processed_commit_shas = load_processed_values(github_advisory_sha)
        processed_advisory_ids = load_processed_values(github_advisory_ids)
        if not processed_commit_shas:
            response = requests.get(
                url,
                headers=github_headers,
                params={"per_page": 1, "page": 1},
                timeout=20,
            )
            response.raise_for_status()
            commits = response.json()
            if not commits:
                logging.info("advisory commit 列表为空，跳过初始化")
                return
            latest_commit_sha = commits[0]['sha']
            append_processed_values(github_advisory_sha, [latest_commit_sha])
            logging.info(f"首次初始化 advisory sha，已记录最新 commit: {latest_commit_sha}，跳过历史 backlog")
            return
        page = 1
        per_page = 100
        max_pages = 3
        new_commits = []
        reached_processed_commit = False

        while page <= max_pages and not reached_processed_commit:
            response = requests.get(
                url,
                headers=github_headers,
                params={"per_page": per_page, "page": page},
                timeout=20,
            )
            response.raise_for_status()
            commits = response.json()
            if not commits:
                break

            for commit in commits:
                commit_sha = commit['sha']
                if commit_sha in processed_commit_shas:
                    reached_processed_commit = True
                    break
                new_commits.append(commit)
            page += 1
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return

    if not new_commits:
        logging.info("没有新的advisory commit被提交")
        return

    successfully_processed_commits = []
    for commit in reversed(new_commits):
        commit_message = commit['commit']['message']
        commit_url = commit['html_url']
        commit_sha = commit['sha']
        logging.info(f"Advisory commit message: {commit_message}")
        logging.info(f"Commit URL: {commit_url}")
        commit_details_url = f"https://api.github.com/repos/github/advisory-database/commits/{commit_sha}"
        try:
            details_response = requests.get(commit_details_url, headers=github_headers, timeout=20)
            details_response.raise_for_status()
        except requests.RequestException as e:
            logging.error(f"获取 advisory commit 详情失败: {commit_sha}, 错误: {e}")
            continue

        commit_details = details_response.json()
        files_changed = commit_details.get('files', [])
        for file in files_changed:
            filename = file['filename']
            status = file['status']
            if not filename.startswith("advisories/") or not filename.endswith('.json'):
                continue
            if status not in {"added", "modified"}:
                continue
            raw_url = f"https://raw.githubusercontent.com/github/advisory-database/{commit_sha}/{filename}"
            pushed = save_file_locally(raw_url, filename, processed_advisory_ids)
            if pushed:
                logging.info(f"已推送 advisory 文件: {filename} ({status})")
            else:
                logging.info(f"已检查 advisory 文件: {filename} ({status})")
        append_processed_values(github_advisory_sha, [commit_sha])
        processed_commit_shas.add(commit_sha)
        successfully_processed_commits.append(commit_sha)

    if successfully_processed_commits:
        logging.info(f"本轮共处理 advisory commits: {len(successfully_processed_commits)}")
            
# 获取最近一次提交的变更文件
def get_latest_commit_files(repo,branch):
    try:
        repo_sha_file = get_repo_sha_file(repo)
        processed_shas = load_repo_processed_shas(repo)
        legacy_processed_shas = load_processed_shas()
        page = 1
        max_pages = 2
        per_page = 100
        new_shas = []
        reached_processed_sha = False

        if not processed_shas:
            init_url = f"https://api.github.com/repos/{repo}/commits?per_page=100&sha={branch}&page=1"
            response = requests.get(init_url, headers=github_headers, timeout=10)
            try:
                response.raise_for_status()
            except requests.HTTPError as e:
                logging.error(f"获取提交列表失败: URL={init_url}, 错误: {str(e)}")
                return []
            commits = response.json()
            if not commits:
                logging.info(f"{repo} 提交列表为空，跳过初始化")
                return []

            bootstrap_match_found = False
            for commit in commits:
                sha = commit["sha"]
                if sha in legacy_processed_shas:
                    append_processed_values(repo_sha_file, [sha])
                    processed_shas.add(sha)
                    bootstrap_match_found = True
                    logging.info(f"{repo} 已根据旧版 sha.txt 迁移提交边界: {sha}")
                    break
            if not bootstrap_match_found:
                latest_commit_sha = commits[0]["sha"]
                append_processed_values(repo_sha_file, [latest_commit_sha])
                logging.info(f"{repo} 首次初始化 repo sha，已记录最新 commit: {latest_commit_sha}，跳过历史 backlog")
                return []

        while page <= max_pages and not reached_processed_sha:
            commits_url = f"https://api.github.com/repos/{repo}/commits?per_page={per_page}&sha={branch}&page={page}"
            response = requests.get(commits_url, headers=github_headers, timeout=10)
            try:
                response.raise_for_status()
            except requests.HTTPError as e:
                logging.error(f"获取提交列表失败: URL={commits_url}, 错误: {str(e)}")
                return []
            commits = response.json()
            if not commits:
                break
            for commit in commits:
                sha = commit["sha"]
                if sha in processed_shas:
                    reached_processed_sha = True
                    break
                new_shas.append(sha)
            page += 1
        if not new_shas:
            logging.info(f"{repo} 无新提交")
            return []
        # 收集所有变更文件
        all_files = []
        for sha in new_shas:
            details_url = f"https://api.github.com/repos/{repo}/commits/{sha}"
            try:
                details_response = requests.get(details_url, headers=github_headers, timeout=15)
                details_response.raise_for_status()
                commit_data = details_response.json()
            except requests.RequestException as e:
                logging.error(f"解析失败: {details_url} - {str(e)}")
                continue
            files = [file["filename"] 
                     for file in commit_data.get("files", [])
                     if file.get("status") == "added" ] # 仅保留新增文件]
            all_files.extend(files)
        # 批量记录 SHA
        append_processed_values(repo_sha_file, new_shas)
        append_processed_values(github_sha, new_shas)
        logging.info(f"{repo} 最新提交 SHA: {new_shas}")
        return all_files
    except requests.RequestException as e:
        logging.error(f"获取 {repo} 最新提交失败: {e}")
        return []

def read_file(repo, branch, file_path):
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{file_path}"

    try:
        response = requests.get(url, headers=github_headers, timeout=10)
        response.raise_for_status()
        if "/wp-content/plugins/" in response.text and "readme.txt" in response.text:
            logging.info(f"❌ {file_path}为版本对比插件")
            return
        if "wp-content/themes" in response.text and "style.css" in response.text:
            logging.info(f"❌ {file_path}为版本对比插件")
            return
        poc_name = extract_repo_yaml_name(response.text, file_path)
        push_text = f"{repo}项目新增PoC推送:\r\n名称：{poc_name}\r\n文件：{file_path}\r\n地址：{url}"
        msg_push.tg_push(push_text)
        msg_push.send_google_sheet("CVE",repo,poc_name,url,file_path)
        logging.info(f"✅ 获取文件内容成功: {file_path} ")
    except requests.RequestException as e:
        logging.error(f"❌ 获取文件内容失败: {file_path} -> {e}")


def get_repo_monitor_folders(repo_config):
    # Normalize repo monitor folders so one repo can watch one or more directory prefixes.
    folders = repo_config.get("folders") or []
    if not folders and repo_config.get("folder"):
        folders = [repo_config["folder"]]
    normalized = []
    for folder in folders:
        folder_text = str(folder or "").strip().rstrip("/")
        if not folder_text:
            continue
        normalized.append(folder_text + "/")
    return normalized


def get_repo_monitor_suffixes(repo_config):
    # Normalize suffix filters and fall back to accepting every file when none are configured.
    suffixes = repo_config.get("suffixes") or []
    normalized = [str(suffix).strip().lower() for suffix in suffixes if str(suffix).strip()]
    return tuple(normalized)


def select_repo_new_files(repo_config, changed_files):
    # Filter added files by configured folders and suffixes while keeping backward compatibility.
    folders = get_repo_monitor_folders(repo_config)
    suffixes = get_repo_monitor_suffixes(repo_config)
    selected = []
    for file_path in changed_files:
        if folders and not any(file_path.startswith(folder) for folder in folders):
            continue
        if suffixes and not file_path.lower().endswith(suffixes):
            continue
        if file_path not in selected:
            selected.append(file_path)
    return selected


def extract_repo_yaml_name(file_text, file_path):
    # Parse a repo PoC YAML and return a human-readable name for push notifications.
    try:
        data = yaml.safe_load(file_text)
    except Exception as exc:
        logging.warning(f"YAML 解析失败，回退到文件名: {file_path} -> {exc}")
        return os.path.basename(file_path)
    if not isinstance(data, dict):
        return os.path.basename(file_path)
    info = data.get("info") or {}
    if isinstance(info, dict):
        name = str(info.get("name") or "").strip()
        if name:
            return name
    top_level_name = str(data.get("name") or "").strip()
    if top_level_name:
        return top_level_name
    poc_id = str(data.get("id") or "").strip()
    if poc_id:
        return poc_id
    return os.path.basename(file_path)


def getRepoPoCs():
    for repo in repo_list:
        repo_name = repo["name"]
        branch = repo.get("branch", "main")
        folders = get_repo_monitor_folders(repo)
        suffixes = get_repo_monitor_suffixes(repo)
        changed_files = get_latest_commit_files(repo_name, branch)
        if changed_files is None:
            logging.error(f"❌ 获取 {repo_name} 的变更文件失败，已跳过")
            continue  # 错误已记录，跳过处理
        new_files = select_repo_new_files(repo, changed_files)
        if new_files:
            logging.info(f"📦 {repo_name} 发现 {len(new_files)} 个新文件:")
            for idx, file in enumerate(new_files, 1):
                logging.info(f"  {idx}. {file}")
            for file in new_files:
                read_file(repo_name, branch, file)
        else:
            folder_desc = ", ".join(folders) if folders else "(all files)"
            suffix_desc = ", ".join(suffixes) if suffixes else "(all suffixes)"
            logging.info(f"✅ {repo_name} 的监控范围无新文件变更: folders={folder_desc} suffixes={suffix_desc}")

def main():
    init()
    #紧急漏洞RSS推送
    logging.info("----------------------------------------------------------")
    logging.info("----------------------紧急漏洞RSS推送-----------------------")
    logging.info("----------------------------------------------------------")
    getRSSNews()
    logging.info("----------------------------------------------------------")
    logging.info("--------------------微信公众号文章推送----------------------")
    logging.info("----------------------------------------------------------")
    monitor_wechat_publishers()
    #紧急漏洞CISA推送
    logging.info("----------------------------------------------------------")
    logging.info("----------------------紧急漏洞CISA推送----------------------")    
    logging.info("----------------------------------------------------------")
    getCISANews()
    #紧急漏洞Github推送
    logging.info("----------------------------------------------------------")
    logging.info("---------------------紧急漏洞Github推送---------------------")
    logging.info("----------------------------------------------------------")
    getGithubVun()
    #CVE披露PoC获取
    logging.info("----------------------------------------------------------")
    logging.info("-------------------Github CVE公开POC获取-------------------")
    logging.info("----------------------------------------------------------")
    getCVE_PoCs()
    #检查昨天热门项目
    logging.info("----------------------------------------------------------")
    logging.info("-------------------检查昨天创建的热门项目-------------------")
    logging.info("----------------------------------------------------------")
    check_yesterday_hot_repos()
    #重点项目监控
    logging.info("----------------------------------------------------------")
    logging.info("---------------------Github 重点项目监控--------------------")
    logging.info("----------------------------------------------------------")
    getRepoPoCs()
    return


if __name__ == '__main__':
    main()
