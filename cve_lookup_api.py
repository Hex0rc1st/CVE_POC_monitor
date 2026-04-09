#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import json
import os
import re
import sys
from typing import Any
from urllib.parse import urlparse

import requests


GITHUB_TOKEN = os.environ.get("github_token")
REQUEST_TIMEOUT = 15

GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "CVE_POC_monitor/cve_lookup_api",
}
if GITHUB_TOKEN:
    GITHUB_API_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
DESCRIPTION_POC_PATTERNS = {
    "poc": re.compile(r"\bpoc\b", re.IGNORECASE),
    "proof_of_concept": re.compile(r"proof[\s_-]*of[\s_-]*concept", re.IGNORECASE),
    "exploit": re.compile(r"\bexploit(?:s|ed|ation)?\b", re.IGNORECASE),
}
URL_POC_PATTERNS = {
    "poc": re.compile(r"(?<![a-z])poc(?![a-z])", re.IGNORECASE),
    "proof_of_concept": re.compile(r"proof[-_/]?of[-_/]?concept", re.IGNORECASE),
    "exploit": re.compile(r"(?<![a-z])exploit(?![a-z])", re.IGNORECASE),
    "reproducer": re.compile(r"reproducer|reproduction|reproduce", re.IGNORECASE),
    "demo": re.compile(r"(?<![a-z])demo(?![a-z])", re.IGNORECASE),
}
CODE_HOSTS = (
    "github.com",
    "gist.github.com",
    "raw.githubusercontent.com",
    "gitlab.com",
)
POC_REFERENCE_HOSTS = (
    "exploit-db.com",
    "www.exploit-db.com",
    "packetstormsecurity.com",
    "www.packetstormsecurity.com",
)
VENDOR_POC_PATH_RULES = (
    ("talosintelligence.com", "/vulnerability_reports/", "vendor_poc_report"),
    ("www.talosintelligence.com", "/vulnerability_reports/", "vendor_poc_report"),
    ("labs.watchtowr.com", "/", "vendor_exploit_writeup"),
    ("www.thezdi.com", "/blog/", "vendor_poc_report"),
    ("thezdi.com", "/blog/", "vendor_poc_report"),
    ("projectdiscovery.io", "/blog/", "vendor_poc_report"),
    ("www.projectdiscovery.io", "/blog/", "vendor_poc_report"),
    ("blog.projectdiscovery.io", "/", "vendor_poc_report"),
    ("vulncheck.com", "/blog/", "vendor_exploit_writeup"),
    ("www.vulncheck.com", "/blog/", "vendor_exploit_writeup"),
    ("rapid7.com", "/blog/", "vendor_exploit_writeup"),
    ("www.rapid7.com", "/blog/", "vendor_exploit_writeup"),
)


def github_get(url: str, params: dict[str, Any] | None = None) -> Any:
    response = requests.get(
        url,
        headers=GITHUB_API_HEADERS,
        params=params,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def normalize_cve_id(cve_id: str) -> str:
    normalized = cve_id.strip().upper()
    if not CVE_PATTERN.fullmatch(normalized):
        raise ValueError("cve_id must match CVE-YYYY-NNNN")
    return normalized


def repository_match_score(item: dict[str, Any], cve_id: str) -> int:
    cve_text = cve_id.lower()
    name_text = " ".join(
        [
            item.get("name") or "",
            item.get("full_name") or "",
        ]
    ).lower()
    description_text = (item.get("description") or "").lower()
    combined_text = f"{name_text} {description_text}"
    score = 0

    if cve_text in name_text:
        score += 5
    if cve_text in description_text:
        score += 4
    if item.get("fork"):
        score -= 2
    if any(keyword in combined_text for keyword in ("poc", "exploit", "demo", "lab", "rce")):
        score += 2

    return score


def search_top_repositories(cve_id: str) -> dict[str, Any]:
    query = f'"{cve_id}" in:name,description,readme'
    data = github_get(
        "https://api.github.com/search/repositories",
        params={
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": 20,
        },
    )
    candidates = []
    for item in data.get("items", []):
        repo = {
            "full_name": item.get("full_name"),
            "html_url": item.get("html_url"),
            "description": item.get("description"),
            "stars": item.get("stargazers_count", 0),
            "updated_at": item.get("updated_at"),
        }
        score = repository_match_score(item, cve_id)
        if score >= 4:
            repo["match_score"] = score
            candidates.append(repo)

    candidates.sort(key=lambda item: (item["stars"], item["match_score"]), reverse=True)
    repos = candidates[:3]
    for repo in repos:
        repo.pop("match_score", None)

    return {
        "query": query,
        "total_count": data.get("total_count", 0),
        "top_repositories": repos,
    }


def find_description_poc_signals(description: str) -> dict[str, Any]:
    matches = [
        label
        for label, pattern in DESCRIPTION_POC_PATTERNS.items()
        if pattern.search(description or "")
    ]
    return {
        "mentions_poc": bool(matches),
        "matched_keywords": matches,
    }


def score_reference(url: str, cve_id: str) -> dict[str, Any] | None:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    url_text = f"{host}{path}?{parsed.query.lower()}"
    reasons = []
    score = 0

    if host.endswith(CODE_HOSTS):
        if path.startswith("/advisories"):
            return None
        reasons.append("code_host")
        score += 2

    if host in POC_REFERENCE_HOSTS:
        reasons.append("poc_reference_host")
        score += 3

    for rule_host, rule_path, reason in VENDOR_POC_PATH_RULES:
        if host == rule_host and rule_path in path:
            reasons.append(reason)
            score += 3
            break

    keyword_hits = [
        label
        for label, pattern in URL_POC_PATTERNS.items()
        if pattern.search(url_text)
    ]
    if keyword_hits:
        reasons.append(f"url_keywords:{','.join(sorted(set(keyword_hits)))}")
        score += 3

    if cve_id.lower() in url_text:
        reasons.append("contains_cve_id")
        score += 1

    if "github.com/advisories/" in url.lower():
        return None

    if score >= 3:
        return {
            "url": url,
            "score": score,
            "reasons": reasons,
        }
    return None


def select_best_advisory(advisories: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not advisories:
        return None
    return sorted(
        advisories,
        key=lambda item: (
            bool(item.get("github_reviewed_at")),
            bool(item.get("severity")),
            item.get("updated_at") or "",
        ),
        reverse=True,
    )[0]


def lookup_advisory(cve_id: str) -> dict[str, Any]:
    advisories = github_get(
        "https://api.github.com/advisories",
        params={"cve_id": cve_id},
    )
    advisory = select_best_advisory(advisories)
    if not advisory:
        return {
            "found": False,
            "advisory_count": 0,
            "selected": None,
        }

    description = advisory.get("description") or ""
    description_signals = find_description_poc_signals(description)
    likely_poc_references = []
    for reference in advisory.get("references", []):
        scored = score_reference(reference, cve_id)
        if scored:
            likely_poc_references.append(scored)

    likely_poc_references.sort(key=lambda item: item["score"], reverse=True)
    selected = {
        "ghsa_id": advisory.get("ghsa_id"),
        "html_url": advisory.get("html_url"),
        "summary": advisory.get("summary"),
        "severity": advisory.get("severity"),
        "published_at": advisory.get("published_at"),
        "updated_at": advisory.get("updated_at"),
        "description_mentions_poc": description_signals["mentions_poc"],
        "description_poc_keywords": description_signals["matched_keywords"],
        "reference_count": len(advisory.get("references", [])),
        "references": advisory.get("references", []),
        "likely_poc_references": likely_poc_references,
    }
    return {
        "found": True,
        "advisory_count": len(advisories),
        "selected": selected,
    }


def build_cve_response(cve_id: str) -> dict[str, Any]:
    normalized_cve = normalize_cve_id(cve_id)
    return {
        "cve_id": normalized_cve,
        "repo_search": search_top_repositories(normalized_cve),
        "advisory": lookup_advisory(normalized_cve),
    }


def load_cve_ids_from_file(file_path: str) -> list[str]:
    cve_ids = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            cve_ids.append(stripped)
    return cve_ids


def collect_cve_ids(args: argparse.Namespace) -> list[str]:
    cve_ids = list(args.cve_ids)
    if args.input_file:
        cve_ids.extend(load_cve_ids_from_file(args.input_file))
    if not cve_ids:
        raise ValueError("at least one CVE ID is required")
    return cve_ids


def build_batch_response(cve_ids: list[str]) -> dict[str, Any]:
    results = []
    errors = []
    for raw_cve_id in cve_ids:
        try:
            results.append(build_cve_response(raw_cve_id))
        except ValueError as exc:
            errors.append(
                {
                    "cve_id": raw_cve_id,
                    "error": "invalid_cve_id",
                    "message": str(exc),
                }
            )
        except requests.HTTPError as exc:
            errors.append(
                {
                    "cve_id": raw_cve_id,
                    "error": "github_api_error",
                    "message": str(exc),
                }
            )
        except requests.RequestException as exc:
            errors.append(
                {
                    "cve_id": raw_cve_id,
                    "error": "network_error",
                    "message": str(exc),
                }
            )
    return {
        "query_count": len(cve_ids),
        "success_count": len(results),
        "error_count": len(errors),
        "results": results,
        "errors": errors,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query GitHub repos and GitHub Advisory data for one or more CVE IDs."
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
        "--compact",
        action="store_true",
        help="Print compact JSON instead of indented JSON.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        cve_ids = collect_cve_ids(args)
    except ValueError as exc:
        print(json.dumps({"error": "invalid_input", "message": str(exc)}, ensure_ascii=False))
        return 2

    if len(cve_ids) == 1:
        try:
            result = build_cve_response(cve_ids[0])
        except ValueError as exc:
            print(json.dumps({"error": "invalid_cve_id", "message": str(exc)}, ensure_ascii=False))
            return 2
        except requests.HTTPError as exc:
            print(json.dumps({"error": "github_api_error", "message": str(exc)}, ensure_ascii=False))
            return 3
        except requests.RequestException as exc:
            print(json.dumps({"error": "network_error", "message": str(exc)}, ensure_ascii=False))
            return 4
    else:
        result = build_batch_response(cve_ids)
        if result["success_count"] == 0 and result["error_count"] > 0:
            return_code = 5
        else:
            return_code = 0

    if args.compact:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    if len(cve_ids) == 1:
        return 0
    return return_code


if __name__ == "__main__":
    sys.exit(main())
