#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import io
import json
import re
import shutil
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any

import requests


REQUEST_TIMEOUT = 30
WXVL_DATA_URL = "https://raw.githubusercontent.com/gelusus/wxvl/main/data.json"
WXVL_TARBALL_URL = "https://codeload.github.com/gelusus/wxvl/tar.gz/refs/heads/main"
CACHE_DIR = Path(".cache/wxvl")
DATA_CACHE_PATH = CACHE_DIR / "data.json"
SNAPSHOT_DIR = CACHE_DIR / "snapshot"
CACHE_TTL_SECONDS = 24 * 60 * 60
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SEARCH_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"
    )
}

HIGH_SIGNAL_KEYWORDS = (
    "漏洞复现",
    "复现",
    "漏洞分析",
    "分析",
    "剖析",
    "详解",
    "利用",
    "利用链",
    "poc",
    "exp",
    "附poc",
    "检测poc",
    "nuclei",
    "脚本",
    "已复现",
    "实战",
)

LOW_SIGNAL_KEYWORDS = (
    "漏洞通告",
    "风险通告",
    "漏洞预警",
    "预警",
    "公告",
    "通告",
    "安全更新",
    "修复建议",
    "风险提示",
    "建议自查",
    "官方",
    "cisa",
    "cnnvd",
    "cnvd",
    "国家漏洞库",
    "补丁日",
)

TITLE_HARD_BLOCK_KEYWORDS = (
    "通告",
    "预警",
    "公告",
    "安全更新",
    "风险提示",
    "补丁日",
)

TITLE_GENERIC_BLOCK_KEYWORDS = (
    "知识库",
    "仓库",
    "合集",
    "免费送",
    "周报",
    "报告",
    "课程",
    "直播",
    "工具",
    "平台",
    "活动",
    "邀请",
    "圈子",
    "赏金",
    "新品",
    "发布会",
)

TITLE_STRONG_SIGNAL_KEYWORDS = (
    "复现",
    "分析",
    "剖析",
    "详解",
    "poc",
    "exp",
    "附poc",
    "已复现",
)

OFFICIAL_VENDOR_KEYWORDS = (
    "奇安信",
    "奇安信 cert",
    "微步",
    "微步在线",
    "微步在线研究响应中心",
    "长亭",
    "长亭科技",
    "长亭安全应急响应中心",
    "360",
    "360数字安全",
    "360漏洞",
    "freebuf",
    "freebuf周报",
)

OFFICIAL_NOTICE_BODY_KEYWORDS = (
    "获取更多安全风险通告",
    "建议用户升级到安全版本",
    "官方已发布漏洞修复版本",
    "风险通告",
    "漏洞通告",
    "修复建议",
    "受影响版本",
    "影响版本",
    "解决方案",
    "缓解措施",
    "厂商已发布",
)


def normalize_cve_id(cve_id: str) -> str:
    # Normalize a CVE identifier and reject malformed input early.
    normalized = cve_id.strip().upper()
    if not CVE_PATTERN.fullmatch(normalized):
        raise ValueError(f"invalid CVE identifier: {cve_id}")
    return normalized


def collect_cve_ids(args: argparse.Namespace) -> list[str]:
    # Collect CVE identifiers from argv or an input file while preserving order.
    raw_values = list(args.cve_ids)
    if args.input_file:
        raw_values.extend(
            line.strip() for line in Path(args.input_file).read_text(encoding="utf-8").splitlines()
        )

    seen = set()
    result = []
    for value in raw_values:
        if not value:
            continue
        normalized = normalize_cve_id(value)
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)

    if not result:
        raise ValueError("provide at least one CVE identifier")
    return result


def ensure_cache_dir() -> None:
    # Create the local cache directory used to persist wxvl metadata and snapshots.
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def is_cache_fresh(path: Path, ttl_seconds: int = CACHE_TTL_SECONDS) -> bool:
    # Check whether a cached file or directory is recent enough to reuse.
    if not path.exists():
        return False
    return (time.time() - path.stat().st_mtime) < ttl_seconds


def fetch_wxvl_data() -> dict[str, str]:
    # Fetch and cache the raw wxvl title index so most queries avoid a repo download.
    ensure_cache_dir()
    if is_cache_fresh(DATA_CACHE_PATH):
        return json.loads(DATA_CACHE_PATH.read_text(encoding="utf-8"))

    response = requests.get(WXVL_DATA_URL, headers=SEARCH_HEADERS, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    payload = response.json()
    DATA_CACHE_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def ensure_wxvl_snapshot() -> Path:
    # Download and extract a fresh wxvl repo snapshot only when title matching is insufficient.
    ensure_cache_dir()
    doc_root = SNAPSHOT_DIR / "wxvl-main" / "doc"
    if is_cache_fresh(doc_root):
        return SNAPSHOT_DIR / "wxvl-main"

    if SNAPSHOT_DIR.exists():
        shutil.rmtree(SNAPSHOT_DIR)
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

    response = requests.get(WXVL_TARBALL_URL, headers=SEARCH_HEADERS, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
        tar.extractall(SNAPSHOT_DIR, filter="data")
    return SNAPSHOT_DIR / "wxvl-main"


def normalize_title_key(value: str) -> str:
    # Collapse punctuation variants so markdown titles can be mapped back to data.json entries.
    cleaned = value.lower()
    cleaned = cleaned.replace("∕", "/").replace("／", "/").replace("|", " ")
    cleaned = cleaned.replace("（", "(").replace("）", ")").replace("：", ":")
    cleaned = re.sub(r"\s+", "", cleaned)
    cleaned = re.sub(r"[^\w\u4e00-\u9fff\-\(\):/+]+", "", cleaned)
    return cleaned


def build_title_index(data: dict[str, str]) -> dict[str, list[dict[str, str]]]:
    # Build a reverse title index from normalized title to original WeChat article links.
    index: dict[str, list[dict[str, str]]] = {}
    for link, title in data.items():
        key = normalize_title_key(title)
        index.setdefault(key, []).append({"title": title, "link": link})
    return index


def find_candidate_urls(title: str, title_index: dict[str, list[dict[str, str]]]) -> list[dict[str, str]]:
    # Map a markdown or filename title back to the original mp.weixin.qq article links.
    return title_index.get(normalize_title_key(title), [])


def extract_article_source(preview: str) -> str:
    # Extract the WeChat account/source name from the first markdown lines when present.
    flat = re.sub(r"\s+", " ", preview).strip()
    if not flat:
        return ""
    for keyword in OFFICIAL_VENDOR_KEYWORDS:
        if keyword.lower() in flat.lower():
            return keyword

    lines = [line.strip().lstrip("#").strip() for line in preview.splitlines() if line.strip()]
    if len(lines) >= 2:
        line = re.sub(r"\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s*$", "", lines[1]).strip()
        line = re.sub(r"^\s*原创\s+", "", line).strip()
        parts = [part.strip() for part in re.split(r"\s{2,}", line) if part.strip()]
        if parts:
            return parts[-1][:80]
        return line[:80]
    return ""


def score_article(title: str, preview: str = "", source_name: str = "") -> tuple[int, list[str], bool]:
    # Score an article by PoC-like signals while filtering out advisory-style notices.
    combined = f"{title}\n{preview}".lower()
    reasons = []
    score = 0

    title_lower = title.lower()
    if any(keyword in title_lower for keyword in TITLE_HARD_BLOCK_KEYWORDS):
        reasons.append("title_notice_like")
        return -10, reasons, True
    if any(keyword in title_lower for keyword in TITLE_GENERIC_BLOCK_KEYWORDS):
        reasons.append("title_generic_content")
        return -8, reasons, True
    source_lower = source_name.lower()
    if source_lower and any(keyword in source_lower for keyword in OFFICIAL_VENDOR_KEYWORDS):
        reasons.append("official_vendor_source")
        return -9, reasons, True

    for keyword in HIGH_SIGNAL_KEYWORDS:
        if keyword.lower() in combined:
            score += 3 if keyword in ("漏洞复现", "复现", "漏洞分析", "附poc", "检测poc", "已复现") else 2
            reasons.append(f"high_signal:{keyword}")

    for keyword in LOW_SIGNAL_KEYWORDS:
        if keyword.lower() in combined:
            score -= 3
            reasons.append(f"low_signal:{keyword}")

    for keyword in OFFICIAL_NOTICE_BODY_KEYWORDS:
        if keyword.lower() in combined:
            score -= 4
            reasons.append(f"notice_template:{keyword}")

    blocked = any(reason == "title_notice_like" for reason in reasons) or score < 1
    return score, reasons, blocked


def make_article_result(title: str, link: str, score: int, reasons: list[str], source: str) -> dict[str, Any]:
    # Normalize a matched article into the output shape used by the CLI.
    return {
        "title": title,
        "link": link,
        "score": score,
        "reasons": reasons,
        "source": source,
    }


def build_markdown_title_map(doc_root: Path) -> dict[str, list[Path]]:
    # Build a local title-to-file map so title hits can be enriched with source metadata quickly.
    mapping: dict[str, list[Path]] = {}
    for file_path in doc_root.rglob("*.md"):
        title = derive_markdown_title(file_path)
        mapping.setdefault(normalize_title_key(title), []).append(file_path)
        mapping.setdefault(normalize_title_key(file_path.stem), []).append(file_path)
    return mapping


def enrich_title_match(
    item: dict[str, Any],
    markdown_title_map: dict[str, list[Path]],
) -> dict[str, Any] | None:
    # Load the matching markdown preview to filter out official notice-style publisher articles.
    key = normalize_title_key(item["title"])
    file_candidates = markdown_title_map.get(key, [])
    preview = ""
    source_name = ""
    if file_candidates:
        preview = read_markdown_preview(file_candidates[0])
        source_name = extract_article_source(preview)
    score, reasons, blocked = score_article(item["title"], preview, source_name)
    if blocked:
        return None

    enriched = dict(item)
    enriched["score"] = score
    enriched["reasons"] = reasons
    if source_name:
        enriched["publisher"] = source_name
    return enriched


def search_by_titles(cve_id: str, data: dict[str, str]) -> list[dict[str, Any]]:
    # Use the title index as the fastest path because it avoids touching the full markdown corpus.
    repo_root = ensure_wxvl_snapshot()
    markdown_title_map = build_markdown_title_map(repo_root / "doc")
    results = []
    for link, title in data.items():
        if cve_id.lower() not in title.lower():
            continue
        enriched = enrich_title_match(
            make_article_result(title, link, 0, [], "title_index"),
            markdown_title_map,
        )
        if enriched is not None:
            results.append(enriched)

    results.sort(key=lambda item: (item["score"], len(item["title"])), reverse=True)
    return dedupe_results(results)


def derive_markdown_title(file_path: Path) -> str:
    # Read the first markdown heading when present; otherwise fall back to the filename stem.
    try:
        with file_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("#"):
                    return line.lstrip("#").strip()
    except OSError:
        pass
    return file_path.stem


def read_markdown_preview(file_path: Path, limit: int = 80) -> str:
    # Read only the first part of a markdown file to keep scoring fast and bounded.
    lines = []
    try:
        with file_path.open("r", encoding="utf-8") as handle:
            for _, line in zip(range(limit), handle):
                lines.append(line.strip())
    except OSError:
        return ""
    return "\n".join(lines)


def search_markdown_files(cve_id: str, doc_root: Path) -> list[Path]:
    # Search cached markdown files with ripgrep when available, then fall back to Python scanning.
    rg_path = shutil.which("rg")
    if rg_path:
        completed = subprocess.run(
            [rg_path, "-l", "-i", cve_id, str(doc_root)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode in (0, 1):
            return [Path(line) for line in completed.stdout.splitlines() if line.strip()]

    matches = []
    needle = cve_id.lower()
    for file_path in doc_root.rglob("*.md"):
        try:
            if needle in file_path.read_text(encoding="utf-8", errors="ignore").lower():
                matches.append(file_path)
        except OSError:
            continue
    return matches


def search_by_markdown(cve_id: str, title_index: dict[str, list[dict[str, str]]]) -> list[dict[str, Any]]:
    # Fall back to markdown-body search when the title index alone cannot find good PoC-like articles.
    repo_root = ensure_wxvl_snapshot()
    doc_root = repo_root / "doc"
    matches = []
    for file_path in search_markdown_files(cve_id, doc_root):
        title = derive_markdown_title(file_path)
        preview = read_markdown_preview(file_path)
        title_lower = title.lower()
        if cve_id.lower() not in title_lower and not any(
            keyword in title_lower for keyword in TITLE_STRONG_SIGNAL_KEYWORDS
        ):
            continue
        source_name = extract_article_source(preview)
        score, reasons, blocked = score_article(title, preview, source_name)
        if blocked or score < 2:
            continue

        url_candidates = find_candidate_urls(title, title_index)
        if not url_candidates:
            url_candidates = find_candidate_urls(file_path.stem, title_index)
        for candidate in url_candidates:
            matches.append(
                make_article_result(
                    candidate["title"],
                    candidate["link"],
                    score,
                    reasons + ["body_match"],
                    "markdown_fallback",
                )
            )
            if source_name:
                matches[-1]["publisher"] = source_name

    matches.sort(key=lambda item: (item["score"], len(item["title"])), reverse=True)
    return dedupe_results(matches)


def dedupe_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Remove duplicate links while preserving the highest-scoring occurrence.
    deduped = []
    seen = set()
    for item in results:
        link = item.get("link")
        if not link or link in seen:
            continue
        seen.add(link)
        deduped.append(item)
    return deduped


def summarize_wxvl_result(result: dict[str, Any]) -> dict[str, Any]:
    # Convert the internal wxvl result into a stable console-friendly JSON shape.
    return {
        "articles": [
            {
                "title": item.get("title", ""),
                "link": item.get("link", ""),
            }
            for item in result.get("articles", [])
            if item.get("link")
        ]
    }


def normalize_publisher_name(value: str) -> str:
    # Normalize a publisher string so configured names can match wxvl markdown metadata reliably.
    return re.sub(r"\s+", "", str(value or "")).strip().lower()


def search_wxvl_publishers(publishers: list[str], max_results: int = 50) -> list[dict[str, Any]]:
    # Find articles whose publisher matches one of the configured WeChat source names.
    normalized_targets = [normalize_publisher_name(item) for item in publishers if str(item).strip()]
    if not normalized_targets:
        return []

    data = fetch_wxvl_data()
    title_index = build_title_index(data)
    repo_root = ensure_wxvl_snapshot()
    doc_root = repo_root / "doc"
    matches = []

    for file_path in sorted(doc_root.rglob("*.md"), reverse=True):
        preview = read_markdown_preview(file_path)
        publisher = extract_article_source(preview)
        publisher_key = normalize_publisher_name(publisher)
        if not publisher_key:
            continue
        if not any(target in publisher_key or publisher_key in target for target in normalized_targets):
            continue

        title = derive_markdown_title(file_path)
        url_candidates = find_candidate_urls(title, title_index)
        if not url_candidates:
            url_candidates = find_candidate_urls(file_path.stem, title_index)

        article_key = url_candidates[0]["link"] if url_candidates else str(file_path.relative_to(doc_root))
        article_link = url_candidates[0]["link"] if url_candidates else ""
        article_title = url_candidates[0]["title"] if url_candidates else title
        matches.append(
            {
                "key": article_key,
                "title": article_title,
                "link": article_link,
                "publisher": publisher,
                "relative_path": str(file_path.relative_to(doc_root)),
            }
        )
        if len(matches) >= max_results:
            break

    return matches


def search_wxvl(cve_id: str, max_results: int) -> dict[str, Any]:
    # Run the wxvl search pipeline and return only PoC-like WeChat article links.
    normalized_cve = normalize_cve_id(cve_id)
    data = fetch_wxvl_data()
    title_index = build_title_index(data)

    title_matches = search_by_titles(normalized_cve, data)
    if len(title_matches) >= max_results:
        selected = title_matches[:max_results]
        return {
            "cve_id": normalized_cve,
            "source": "wechat",
            "strategy": "title_index_only",
            "total_results": len(selected),
            "articles": selected,
        }

    markdown_matches = search_by_markdown(normalized_cve, title_index)
    merged = dedupe_results(title_matches + markdown_matches)[:max_results]
    return {
        "cve_id": normalized_cve,
        "source": "wechat",
        "strategy": "title_index_then_markdown_fallback",
        "total_results": len(merged),
        "articles": merged,
    }


def parse_args() -> argparse.Namespace:
    # Parse CLI arguments for wxvl CVE article lookup.
    parser = argparse.ArgumentParser(
        description="Search PoC-like WeChat articles for one or more CVEs from the wxvl archive."
    )
    parser.add_argument("cve_ids", nargs="*", help="One or more CVE identifiers.")
    parser.add_argument("--input-file", help="Read CVE identifiers from a text file, one per line.")
    parser.add_argument("--max-results", type=int, default=5, help="Maximum number of article links per CVE.")
    parser.add_argument("--compact", action="store_true", help="Print compact JSON.")
    return parser.parse_args()


def main() -> int:
    # Execute the wxvl search flow and print JSON grouped by CVE.
    args = parse_args()
    try:
        cve_ids = collect_cve_ids(args)
    except ValueError as exc:
        print(json.dumps({"error": "invalid_input", "message": str(exc)}, ensure_ascii=False))
        return 2

    payload = {}
    errors = []
    for cve_id in cve_ids:
        try:
            result = search_wxvl(cve_id, args.max_results)
            payload[cve_id] = {"wechat": summarize_wxvl_result(result)}
        except requests.HTTPError as exc:
            error = {"cve_id": cve_id, "error": "http_error", "message": str(exc)}
            payload[cve_id] = {"wechat": {"error": error}}
            errors.append(error)
        except requests.RequestException as exc:
            error = {"cve_id": cve_id, "error": "network_error", "message": str(exc)}
            payload[cve_id] = {"wechat": {"error": error}}
            errors.append(error)

    if args.compact:
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 5 if errors and len(errors) == len(cve_ids) else 0


if __name__ == "__main__":
    raise SystemExit(main())
