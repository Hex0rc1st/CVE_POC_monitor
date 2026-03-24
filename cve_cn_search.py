#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import json
import html
import xml.etree.ElementTree as ET
from collections import OrderedDict
from typing import Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


REQUEST_TIMEOUT = 20
SEARCH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"
}

CN_QUERY_TEMPLATES = (
    "\"{cve}\"",
    "\"{cve}\" 漏洞分析",
    "\"{cve}\" 复现",
    "\"{cve}\" 利用",
    "\"{cve}\" 中文",
)

CN_SITE_QUERY_TEMPLATES = (
    'site:research.qianxin.com "{cve}"',
    'site:cloud.tencent.com "{cve}"',
)

CN_SOURCE_RULES = (
    ("research.qianxin.com", "security_research"),
    ("cloud.tencent.com", "security_research"),
    ("secrss.com", "security_media"),
    ("cn-sec.com", "security_media"),
    ("nsfocus.com", "security_vendor"),
    ("csdn.net", "blog_or_forum"),
    ("cnblogs.com", "blog_or_forum"),
    ("freebuf.com", "security_media"),
    ("anquanke.com", "security_media"),
    ("xz.aliyun.com", "security_media"),
    ("52pojie.cn", "forum"),
    ("buaq.net", "security_aggregator"),
    ("seebug.org", "security_media"),
    ("qq.com", "portal_or_wechat"),
    ("sohu.com", "portal"),
    ("163.com", "portal"),
)

CN_PREFERRED_REASON_PREFIXES = (
    "security_research",
    "security_media",
    "security_vendor",
    "blog_or_forum",
    "forum",
    "security_aggregator",
    "portal",
    "portal_or_wechat",
)

LOW_QUALITY_HOSTS = (
    "zhihu.com",
    "nvd.nist.gov",
    "github.com",
    "security.paloaltonetworks.com",
    "cve.mitre.org",
)

NOTICE_LIKE_HOSTS = (
    "cisa.gov",
    "tenable.com",
    "kroll.com",
    "cve.org",
    "cvedetails.com",
    "security.paloaltonetworks.com",
    "linkedin.com",
    "nti.nsfocus.com",
)

HIGH_SIGNAL_KEYWORDS = (
    "复现",
    "漏洞复现",
    "漏洞分析",
    "技术分析",
    "利用",
    "getshell",
    "poc",
    "脚本",
    "批量检测",
    "一键检测",
    "nuclei",
    "深度剖析",
    "剖析",
)

LOW_SIGNAL_KEYWORDS = (
    "通告",
    "公告",
    "预警",
    "修复",
    "风险提示",
    "advisory",
    "guidance",
    "alert",
    "record",
    "workaround",
    "mitigation",
)


def normalize_cve_id(cve_id: str) -> str:
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise ValueError("cve_id must start with CVE-")
    return cve_id


def build_queries(cve_id: str) -> list[str]:
    return [template.format(cve=cve_id) for template in CN_QUERY_TEMPLATES]


def build_site_queries(cve_id: str) -> list[str]:
    return [template.format(cve=cve_id) for template in CN_SITE_QUERY_TEMPLATES]


def fetch_cve_context(cve_id: str) -> dict[str, Any]:
    # Fetch CVE metadata from NVD so site searches can expand from raw CVE IDs to product keywords.
    response = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve_id},
        headers=SEARCH_HEADERS,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return {"description": "", "keywords": []}

    cve = vulnerabilities[0].get("cve", {})
    descriptions = [
        item.get("value", "").strip()
        for item in cve.get("descriptions", [])
        if item.get("lang") == "en" and item.get("value")
    ]
    description = descriptions[0] if descriptions else ""

    raw_keywords = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 5:
                    vendor = parts[3].replace("_", " ").strip()
                    product = parts[4].replace("_", " ").strip()
                    combined = " ".join(part for part in (vendor, product) if part and part != "*").strip()
                    if combined:
                        raw_keywords.append(combined)
                    if product and product != "*":
                        raw_keywords.append(product)

    if description:
        first_sentence = description.split(".")[0].strip()
        lowered_sentence = first_sentence.lower()
        if " of " in lowered_sentence:
            suffix = first_sentence[lowered_sentence.find(" of ") + 4:].strip()
            if suffix:
                raw_keywords.append(suffix)
        for marker in (
            " vulnerability",
            " may enable",
            " may allow",
            " could allow",
            " allows",
        ):
            if marker in lowered_sentence:
                prefix = first_sentence[:lowered_sentence.find(marker)].strip()
                if prefix:
                    raw_keywords.append(prefix)

    keywords = []
    for keyword in raw_keywords:
        normalized = " ".join(keyword.replace("-", " ").split()).strip()
        if len(normalized) < 4:
            continue
        if len(normalized) > 60:
            continue
        if normalized.lower().startswith(cve_id.lower()):
            continue
        if normalized not in keywords:
            keywords.append(normalized)

    return {"description": description, "keywords": keywords[:8]}


def extract_embedded_json_object(text: str, key: str) -> dict[str, Any] | None:
    # Extract a JSON object embedded inside a larger HTML document by key name.
    marker = f'"{key}":'
    start = text.find(marker)
    if start == -1:
        return None

    index = start + len(marker)
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] != "{":
        return None

    depth = 0
    in_string = False
    escaped = False
    for end in range(index, len(text)):
        char = text[end]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        else:
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[index:end + 1])
                    except json.JSONDecodeError:
                        return None
    return None


def search_qianxin_site(cve_id: str) -> list[dict[str, Any]]:
    # Query Qianxin's native site search and return article links from archives pages.
    response = requests.get(
        "https://research.qianxin.com/",
        params={"s": cve_id},
        headers=SEARCH_HEADERS,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    results = []
    seen_links = set()
    for link_node in soup.select("a[href]"):
        href = link_node.get("href", "").strip()
        title = link_node.get_text(" ", strip=True)
        if not href or not title:
            continue
        if href.startswith("/"):
            href = f"https://research.qianxin.com{href}"
        if "research.qianxin.com/archives/" not in href:
            continue
        if href in seen_links:
            continue
        seen_links.add(href)
        results.append(
            {
                "title": title,
                "link": href,
                "summary": "",
                "source_query": f"native:research.qianxin.com:{cve_id}",
            }
        )
    return results


def search_tencent_cloud_site(cve_id: str) -> list[dict[str, Any]]:
    # Query Tencent Cloud's native article search and read the embedded search data payload.
    response = requests.get(
        f"https://cloud.tencent.com/developer/search/article-{cve_id}",
        headers=SEARCH_HEADERS,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    search_data = extract_embedded_json_object(response.text, "searchData")
    if not search_data:
        return []

    results = []
    seen_links = set()
    for item in search_data.get("list", []):
        article_id = item.get("articleId") or item.get("id")
        title = (item.get("title") or "").strip()
        summary = (
            item.get("summary")
            or item.get("abstract")
            or item.get("brief")
            or item.get("posterSummary")
            or ""
        ).strip()
        if not article_id or not title:
            continue

        link = f"https://cloud.tencent.com/developer/article/{article_id}"
        if link in seen_links:
            continue
        seen_links.add(link)
        results.append(
            {
                "title": title,
                "link": link,
                "summary": summary,
                "source_query": f"native:cloud.tencent.com:{cve_id}",
            }
        )
    return results


def parse_xz_search_results(data_html: str, keyword: str, cve_id: str) -> list[dict[str, Any]]:
    # Parse Xianzhi search result cards returned by /search/data.
    soup = BeautifulSoup(data_html, "html.parser")
    results = []
    seen_links = set()
    for item in soup.select(".news_item"):
        title_node = item.select_one("a.news_title")
        summary_node = item.select_one("p")
        if not title_node:
            continue
        link = (title_node.get("href") or "").strip()
        title = title_node.get_text(" ", strip=True)
        summary = summary_node.get_text(" ", strip=True) if summary_node else ""
        if not link or not title or link in seen_links:
            continue
        seen_links.add(link)
        results.append(
            {
                "title": html.unescape(title),
                "link": link,
                "summary": html.unescape(summary),
                "source_query": f"native:xz.aliyun.com:{keyword}",
                "matched_keyword": keyword,
                "match_mode": "keyword",
                "cve_id": cve_id,
            }
        )
    return results


def search_xianzhi_site(cve_id: str, keywords: list[str]) -> list[dict[str, Any]]:
    # Query Xianzhi's search API with CVE-derived keywords and return parsed article cards.
    results = []
    for keyword in keywords:
        response = requests.get(
            "https://xz.aliyun.com/search/data",
            params={"type": 3, "limit": 10, "page": 1, "keywords": keyword},
            headers={**SEARCH_HEADERS, "X-Requested-With": "XMLHttpRequest"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        data_html = payload.get("data", "")
        if not data_html:
            continue
        results.extend(parse_xz_search_results(data_html, keyword, cve_id))
    return results


def collect_native_results(cve_id: str, cve_context: dict[str, Any]) -> list[dict[str, Any]]:
    native_results = []
    native_results.extend(search_qianxin_site(cve_id))
    native_results.extend(search_tencent_cloud_site(cve_id))
    native_results.extend(search_xianzhi_site(cve_id, cve_context.get("keywords", [])))
    return native_results


def search_bing_rss(query: str) -> list[dict[str, Any]]:
    # Query Bing RSS so search pages can be parsed without a browser runtime.
    response = requests.get(
        "https://www.bing.com/search",
        params={"format": "rss", "q": query},
        headers=SEARCH_HEADERS,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    root = ET.fromstring(response.text)
    results = []
    for item in root.findall("./channel/item"):
        title = (item.findtext("title", "") or "").strip()
        link = (item.findtext("link", "") or "").strip()
        summary = (item.findtext("description", "") or "").strip()
        if not title or not link:
            continue
        results.append(
            {
                "title": title,
                "link": link,
                "summary": summary,
                "source_query": query,
            }
        )
    return results


def get_expected_site_host(query: str) -> str | None:
    prefix = "site:"
    if not query.startswith(prefix):
        return None
    remainder = query[len(prefix):]
    return remainder.split()[0].strip().lower()


def filter_raw_results(results: list[dict[str, Any]], cve_id: str) -> list[dict[str, Any]]:
    filtered = []
    cve_text = cve_id.lower()
    for result in results:
        link = result.get("link", "")
        title = result.get("title", "")
        summary = result.get("summary", "")
        source_query = result.get("source_query", "")
        host = urlparse(link).netloc.lower()
        expected_site_host = get_expected_site_host(source_query)
        combined_text = f"{title} {summary} {link}".lower()
        matched_keyword = (result.get("matched_keyword") or "").lower()

        if expected_site_host and not host.endswith(expected_site_host):
            continue
        if cve_text not in combined_text:
            if not matched_keyword or matched_keyword not in combined_text:
                continue
            result["match_mode"] = "keyword"
        else:
            result["match_mode"] = "cve"
        if result.get("match_mode") == "keyword" and source_query.startswith("native:xz.aliyun.com:"):
            result["keyword_match_only"] = True
        if result.get("match_mode") == "keyword" and len(matched_keyword) < 6:
            continue
        if not contains_chinese(f"{title} {summary}") and not host.endswith((".cn", "cloud.tencent.com")):
            continue
        filtered.append(result)
    return filtered


def score_result(result: dict[str, Any], cve_id: str) -> dict[str, Any]:
    link = result.get("link", "")
    title = result.get("title", "")
    summary = result.get("summary", "")
    parsed = urlparse(link)
    host = parsed.netloc.lower()
    combined_text = f"{title} {summary}".lower()
    reasons = []
    score = 0

    if any(host.endswith(domain) for domain in LOW_QUALITY_HOSTS):
        reasons.append("low_quality_host")
        score -= 3

    for domain, label in CN_SOURCE_RULES:
        if host.endswith(domain):
            reasons.append(label)
            score += 3
            break

    keyword_hits = [keyword for keyword in HIGH_SIGNAL_KEYWORDS if keyword.lower() in combined_text]
    if keyword_hits:
        reasons.append(f"high_signal:{','.join(sorted(set(keyword_hits)))}")
        score += 3

    low_signal_hits = [keyword for keyword in LOW_SIGNAL_KEYWORDS if keyword.lower() in combined_text]
    if low_signal_hits:
        reasons.append(f"low_signal:{','.join(sorted(set(low_signal_hits)))}")
        score -= 1

    if cve_id.lower() in combined_text:
        reasons.append("contains_cve_id")
        score += 2
    elif result.get("keyword_match_only"):
        reasons.append(f"keyword_match_only:{result.get('matched_keyword', '')}")
        score += 1

    return {
        "title": title,
        "link": link,
        "summary": summary,
        "source_query": result.get("source_query", ""),
        "score": score,
        "reasons": reasons,
        "host": host,
        "matched_keyword": result.get("matched_keyword", ""),
        "match_mode": result.get("match_mode", "cve"),
    }


def deduplicate_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped = OrderedDict()
    for result in results:
        link = result.get("link", "")
        if not link:
            continue
        if link not in deduped or result["score"] > deduped[link]["score"]:
            deduped[link] = result
    return list(deduped.values())


def is_cn_preferred_result(result: dict[str, Any]) -> bool:
    host = result.get("host", "")
    reasons = result.get("reasons", [])
    if host.endswith(".cn"):
        return True
    return any(reason in CN_PREFERRED_REASON_PREFIXES for reason in reasons)


def contains_chinese(text: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in text)


def has_article_signal(result: dict[str, Any]) -> bool:
    combined = f"{result.get('title', '')} {result.get('summary', '')}".lower()
    strong_signals = (
        "漏洞分析",
        "技术分析",
        "复现",
        "漏洞复现",
        "利用",
        "深度剖析",
        "剖析",
        "poc",
        "proof of concept",
        "getshell",
        "脚本",
        "nuclei",
        "深度剖析",
        "剖析",
    )
    return any(signal.lower() in combined for signal in strong_signals)


def is_notice_like(result: dict[str, Any]) -> bool:
    host = result.get("host", "")
    title = result.get("title", "").lower()
    summary = result.get("summary", "").lower()
    combined = f"{title} {summary}"
    if any(host.endswith(domain) for domain in NOTICE_LIKE_HOSTS):
        return True
    if result.get("link", "").lower().endswith(".pdf"):
        return True
    if any(keyword.lower() in title for keyword in LOW_SIGNAL_KEYWORDS):
        return True
    if any(
        keyword.lower() in combined
        for keyword in (
            "cve record",
            "security advisory",
            "漏洞预警",
            "漏洞通告",
            "安全通告",
            "漏洞通报",
            "安全通报",
            "风险提示",
            "修复建议",
            "announcement",
        )
    ):
        return True
    return False


def search_cn_content(cve_id: str, max_results: int) -> dict[str, Any]:
    normalized_cve = normalize_cve_id(cve_id)
    cve_context = {"description": "", "keywords": []}
    queries = build_queries(normalized_cve)
    site_queries = build_site_queries(normalized_cve)
    raw_results = []
    query_errors = []

    try:
        cve_context = fetch_cve_context(normalized_cve)
    except requests.HTTPError as exc:
        query_errors.append(
            {
                "query": f"nvd:{normalized_cve}",
                "error": "search_error",
                "message": str(exc),
            }
        )
    except requests.RequestException as exc:
        query_errors.append(
            {
                "query": f"nvd:{normalized_cve}",
                "error": "network_error",
                "message": str(exc),
            }
        )

    try:
        raw_results.extend(collect_native_results(normalized_cve, cve_context))
    except requests.HTTPError as exc:
        query_errors.append(
            {
                "query": "native:site-search",
                "error": "search_error",
                "message": str(exc),
            }
        )
    except requests.RequestException as exc:
        query_errors.append(
            {
                "query": "native:site-search",
                "error": "network_error",
                "message": str(exc),
            }
        )

    for query in queries:
        try:
            raw_results.extend(search_bing_rss(query))
        except requests.HTTPError as exc:
            query_errors.append(
                {
                    "query": query,
                    "error": "search_error",
                    "message": str(exc),
                }
            )
        except requests.RequestException as exc:
            query_errors.append(
                {
                    "query": query,
                    "error": "network_error",
                    "message": str(exc),
                }
            )

    filtered_raw_results = filter_raw_results(raw_results, normalized_cve)
    scored_results = [score_result(result, normalized_cve) for result in filtered_raw_results]
    deduped_results = deduplicate_results(scored_results)
    deduped_results.sort(key=lambda item: (item["score"], item["title"]), reverse=True)
    preferred_results = [
        item for item in deduped_results
        if "low_quality_host" not in item["reasons"]
        and is_cn_preferred_result(item)
        and has_article_signal(item)
        and not is_notice_like(item)
    ]
    likely_results = [
        item for item in preferred_results
        if item["score"] >= 4
        and not any(reason.startswith("keyword_match_only:") for reason in item["reasons"])
    ][:max_results]
    likely_links = {item["link"] for item in likely_results}
    top_results = [
        item for item in preferred_results
        if item["link"] not in likely_links
        and not any(reason.startswith("keyword_match_only:") for reason in item["reasons"])
    ][:max_results]
    fallback_results = [
        item for item in deduped_results
        if "low_quality_host" not in item["reasons"]
        and has_article_signal(item)
        and not is_notice_like(item)
        and item["link"] not in likely_links
        and (
            any(reason.startswith("keyword_match_only:") for reason in item["reasons"])
            or (
                not is_cn_preferred_result(item)
                and contains_chinese(f"{item.get('title', '')} {item.get('summary', '')}")
            )
        )
    ][:max_results]

    return {
        "cve_id": normalized_cve,
        "engine": "bing_rss+native",
        "queries": queries,
        "site_queries": site_queries,
        "expanded_keywords": cve_context.get("keywords", []),
        "query_errors": query_errors,
        "total_results": len(deduped_results),
        "likely_cn_articles": likely_results,
        "top_results": top_results,
        "fallback_results": fallback_results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search Chinese internet content for one or more CVE IDs."
    )
    parser.add_argument("cve_ids", nargs="+", help="One or more CVE identifiers.")
    parser.add_argument(
        "--max-results",
        type=int,
        default=10,
        help="Maximum number of top results to return for each CVE.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print compact JSON instead of indented JSON.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = []
    errors = []
    for cve_id in args.cve_ids:
        try:
            results.append(search_cn_content(cve_id, args.max_results))
        except ValueError as exc:
            errors.append({"cve_id": cve_id, "error": "invalid_cve_id", "message": str(exc)})
        except requests.HTTPError as exc:
            errors.append({"cve_id": cve_id, "error": "search_error", "message": str(exc)})
        except requests.RequestException as exc:
            errors.append({"cve_id": cve_id, "error": "network_error", "message": str(exc)})

    payload = {
        "query_count": len(args.cve_ids),
        "success_count": len(results),
        "error_count": len(errors),
        "results": results,
        "errors": errors,
    }
    if args.compact:
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if not errors else 5


if __name__ == "__main__":
    raise SystemExit(main())
