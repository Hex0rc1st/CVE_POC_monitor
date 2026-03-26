#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import json
from datetime import datetime
from pathlib import Path

import requests

from cve_cn_search import search_cn_content
from cve_lookup_api import build_cve_response, collect_cve_ids
from cve_wxvl_search import search_wxvl, summarize_wxvl_result


LOG_DIR = Path("logs")


def ensure_log_dir() -> Path:
    # Create the local log directory used to store raw per-source results.
    LOG_DIR.mkdir(exist_ok=True)
    return LOG_DIR


def build_timestamp() -> str:
    # Generate a stable timestamp suffix for log file names.
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def write_json_log(file_path: Path, payload: dict) -> None:
    # Persist raw source output to disk for later troubleshooting.
    file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def summarize_github_result(result: dict) -> dict:
    # Convert the GitHub source result into a compact summary for the unified output.
    repo_search = result.get("repo_search", {})
    advisory = result.get("advisory", {}).get("selected", {})
    return {
        "repos": [
            item.get("html_url")
            for item in repo_search.get("top_repositories", [])
            if item.get("html_url")
        ],
        "poc_references": [
            item.get("url")
            for item in advisory.get("likely_poc_references", [])
            if item.get("url")
        ],
    }


def summarize_browser_result(result: dict) -> dict:
    # Convert the Chinese search source result into a compact summary for the unified output.
    return {
        "likely_cn_articles": [
            {
                "title": item.get("title", ""),
                "link": item.get("link", ""),
            }
            for item in result.get("likely_cn_articles", [])
            if item.get("link")
        ],
        "top_results": [
            item.get("link") for item in result.get("top_results", []) if item.get("link")
        ],
        "fallback_results": [
            item.get("link") for item in result.get("fallback_results", []) if item.get("link")
        ],
    }


def run_cve_poc_search(cve_ids: list[str], max_results: int) -> dict:
    # Execute GitHub, CN browser, and wxvl searches for each CVE and merge them into one payload.
    github_results = []
    github_errors = []
    browser_results = []
    browser_errors = []
    wxvl_results = []
    wxvl_errors = []
    summary = {}

    for cve_id in cve_ids:
        normalized_cve = cve_id.strip().upper()
        github_result = None
        browser_result = None
        wxvl_result = None

        try:
            github_result = build_cve_response(normalized_cve)
            github_results.append(github_result)
        except ValueError as exc:
            github_error = {"cve_id": normalized_cve, "error": "invalid_cve_id", "message": str(exc)}
            github_errors.append(github_error)
        except requests.HTTPError as exc:
            github_error = {"cve_id": normalized_cve, "error": "github_api_error", "message": str(exc)}
            github_errors.append(github_error)
        except requests.RequestException as exc:
            github_error = {"cve_id": normalized_cve, "error": "network_error", "message": str(exc)}
            github_errors.append(github_error)
        else:
            github_error = None

        try:
            browser_result = search_cn_content(normalized_cve, max_results)
            browser_results.append(browser_result)
        except ValueError as exc:
            browser_error = {"cve_id": normalized_cve, "error": "invalid_cve_id", "message": str(exc)}
            browser_errors.append(browser_error)
        except requests.HTTPError as exc:
            browser_error = {"cve_id": normalized_cve, "error": "search_error", "message": str(exc)}
            browser_errors.append(browser_error)
        except requests.RequestException as exc:
            browser_error = {"cve_id": normalized_cve, "error": "network_error", "message": str(exc)}
            browser_errors.append(browser_error)
        else:
            browser_error = None

        try:
            wxvl_result = search_wxvl(normalized_cve, max_results)
            wxvl_results.append(wxvl_result)
        except ValueError as exc:
            wxvl_error = {"cve_id": normalized_cve, "error": "invalid_cve_id", "message": str(exc)}
            wxvl_errors.append(wxvl_error)
        except requests.HTTPError as exc:
            wxvl_error = {"cve_id": normalized_cve, "error": "search_error", "message": str(exc)}
            wxvl_errors.append(wxvl_error)
        except requests.RequestException as exc:
            wxvl_error = {"cve_id": normalized_cve, "error": "network_error", "message": str(exc)}
            wxvl_errors.append(wxvl_error)
        else:
            wxvl_error = None

        summary[normalized_cve] = {
            "github": summarize_github_result(github_result) if github_result else {"error": github_error},
            "brower": summarize_browser_result(browser_result) if browser_result else {"error": browser_error},
            "wechat": summarize_wxvl_result(wxvl_result) if wxvl_result else {"error": wxvl_error},
        }

    timestamp = build_timestamp()
    log_dir = ensure_log_dir()
    github_log_path = log_dir / f"github_search_{timestamp}.json"
    browser_log_path = log_dir / f"cn_search_{timestamp}.json"
    wxvl_log_path = log_dir / f"wxvl_search_{timestamp}.json"

    write_json_log(
        github_log_path,
        {
            "query_count": len(cve_ids),
            "success_count": len(github_results),
            "error_count": len(github_errors),
            "results": github_results,
            "errors": github_errors,
        },
    )
    write_json_log(
        browser_log_path,
        {
            "query_count": len(cve_ids),
            "success_count": len(browser_results),
            "error_count": len(browser_errors),
            "results": browser_results,
            "errors": browser_errors,
        },
    )
    write_json_log(
        wxvl_log_path,
        {
            "query_count": len(cve_ids),
            "success_count": len(wxvl_results),
            "error_count": len(wxvl_errors),
            "results": wxvl_results,
            "errors": wxvl_errors,
        },
    )

    return {
        "summary": summary,
        "logs": {
            "github": str(github_log_path),
            "brower": str(browser_log_path),
            "wechat": str(wxvl_log_path),
        },
        "errors": {
            "github": github_errors,
            "brower": browser_errors,
            "wechat": wxvl_errors,
        },
    }


def parse_args() -> argparse.Namespace:
    # Parse CLI arguments for the multi-source CVE PoC search entrypoint.
    parser = argparse.ArgumentParser(
        description="Run GitHub, Chinese internet, and WeChat CVE PoC searches together."
    )
    parser.add_argument(
        "cve_ids",
        nargs="*",
        help="One or more CVE identifiers, for example CVE-2024-3094 CVE-2024-3400",
    )
    parser.add_argument(
        "--input-file",
        help="Read CVE identifiers from a text file, one CVE per line.",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=10,
        help="Maximum results to return per source for each CVE.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print compact JSON instead of indented JSON.",
    )
    return parser.parse_args()


def main() -> int:
    # Execute the multi-source search flow and print the merged JSON payload.
    args = parse_args()
    try:
        cve_ids = collect_cve_ids(args)
    except ValueError as exc:
        print(json.dumps({"error": "invalid_input", "message": str(exc)}, ensure_ascii=False))
        return 2

    payload = run_cve_poc_search(cve_ids, args.max_results)
    if args.compact:
        print(json.dumps(payload["summary"], ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))

    if payload["errors"]["github"] and payload["errors"]["brower"] and payload["errors"]["wechat"] and not payload["summary"]:
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
