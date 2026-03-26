[中文说明](./README_zh.md)

# CVE_POC_monitor

CVE_POC_monitor is an automated vulnerability intelligence monitor that aggregates high-signal CVE/PoC information and pushes alerts to messaging channels and Google Sheets.

## What It Does

- Monitors multiple vulnerability/security RSS feeds and pushes newly discovered high-risk items.
- Tracks newly created GitHub repositories by CVE-related keywords (for example `CVE-2024-`, `CVE-2025-`, `CVE-2026-`) to discover public PoCs quickly.
- Watches selected GitHub repositories/folders for newly added PoC files.
- Pulls CISA KEV (Known Exploited Vulnerabilities) CSV updates and pushes newly added CVEs.
- Monitors the GitHub Advisory Database commit stream and extracts newly added advisory JSON files.
- Optionally runs LLM analysis (`LLM.py`) to extract HTTP request payload clues from raw PoC scripts.

## Data Sources Referenced by This Project

### 1) Official/API data

- **GitHub Search API**: repository discovery by CVE keywords.
- **wxvl index data**: `https://raw.githubusercontent.com/gelusus/wxvl/main/data.json`
- **wxvl repository snapshot**: `https://codeload.github.com/gelusus/wxvl/tar.gz/refs/heads/main`
- **GitHub Commits/Contents API**: advisory updates and monitored repo file changes.
- **GitHub Advisory raw JSON**: parsed for aliases, severity, details.
- **CISA KEV CSV**:  
  `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv`
- **Google Apps Script Webhook** (user-provided): stores/retrieves monitoring records (sheets like `CVE`, `raw`, `Emergency Vulnerability`).

### 2) Local state / rule data

- `utils/monitor_list.yaml`: keyword list + target repos/folders.
- `utils/clean.yaml`: dedup/ignore list (already processed project names).
- `utils/known_object.yaml`: key product/object matching list for advisory filtering.
- `utils/CISA.txt`: local record of already-pushed CISA CVEs.
- `utils/sha.txt`: processed GitHub commit SHAs.
- `RSSs/*.json`: local snapshots of previously seen RSS entries for deduplication.

## RSS Sources (Configured in `RSSs/rss_config.json`)

- GitLab Security Releases: `https://about.gitlab.com/security-releases.xml`
- Spring Security: `https://spring.io/security.atom`
- Fortinet PSIRT: `https://www.fortiguard.com/rss/ir.xml`
- Ivanti Security Advisory: `https://www.ivanti.com/blog/topics/security-advisory/rss`
- Google Chrome Releases: `https://chromereleases.googleblog.com/feeds/posts/default?alt=rss`
- Palo Alto Networks Security Advisories: `https://security.paloaltonetworks.com/rss.xml`
- SecurityOnline: `https://securityonline.info/feed`
- watchTowr Labs: `https://labs.watchtowr.com/rss`
- GBHackers: `https://gbhackers.com/feed/`
- Picus Security: `https://www.picussecurity.com/resource/rss.xml`
- Rapid7: `https://www.rapid7.com/rss.xml`
- The Hacker News: `https://feeds.feedburner.com/TheHackersNews`
- Zero Day Initiative: `https://www.zerodayinitiative.com/blog/?format=rss`

## Notification & Storage Targets

- Telegram (`tg_token`, `tg_chat_id`)
- WeCom/WeChat webhook (`wechat_token`)
- Google Sheets via Apps Script (`google_sheet_token`)

## Quick Start

```bash
pip install -r requirements.txt

export github_token="..."
export google_sheet_token="..."
export tg_chat_id="..."
export tg_token="..."
export wechat_token="..."
export baidu_appid="..."
export baidu_appkey="..."

python3 main.py
```

Optional LLM step:

```bash
export llm_url="..."
export llm_api_key="..."
python3 LLM.py
```

## CVE Lookup

This repository also includes a lightweight CVE lookup script.

Run the query directly with a CVE ID:

```bash
export github_token="..."
python3 cve_lookup_api.py CVE-2024-3094
```

Batch query with multiple CVE IDs:

```bash
python3 cve_lookup_api.py CVE-2024-3094 CVE-2024-3400 CVE-2025-0282
```

Batch query from a file:

```bash
python3 cve_lookup_api.py --input-file cve_list.txt
```

Compact output:

```bash
python3 cve_lookup_api.py CVE-2024-3094 --compact
```

The script returns:

- top 3 GitHub repositories for the CVE by stars
- whether the GitHub Advisory description mentions PoC-related keywords
- likely PoC references extracted from the advisory references list

## Chinese Search

This repository also includes a script for searching Chinese internet content about a CVE.

```bash
python3 cve_cn_search.py CVE-2024-3400
```

Multiple CVEs:

```bash
python3 cve_cn_search.py CVE-2024-3400 CVE-2025-0282
```

The script scores Chinese blogs, forums, and security writeups and filters notice-like content.

## WeChat PoC Search

This repository also includes a script for searching PoC-like WeChat articles from the `gelusus/wxvl` archive.

```bash
python3 cve_wxvl_search.py CVE-2024-3400
```

Multiple CVEs:

```bash
python3 cve_wxvl_search.py CVE-2024-3400 CVE-2025-0282
```

The script uses the wxvl title index first, falls back to cached markdown only when needed, and filters official advisory-style publishers such as QAX, 360, ThreatBook, Chaitin, and FreeBuf.

## Multi-Source PoC Search

Use the unified multi-source entrypoint to query GitHub, Chinese web results, and WeChat articles together.

```bash
python3 cve_poc_search.py CVE-2024-3400
```

Multiple CVEs:

```bash
python3 cve_poc_search.py CVE-2024-3400 CVE-2025-0282
```

From file:

```bash
python3 cve_poc_search.py --input-file cve_list.txt
```

Compact output:

```bash
python3 cve_poc_search.py CVE-2024-3400 --compact
```

Output shape:

```json
{
  "CVE-2024-3400": {
    "github": {"repos": [], "poc_references": []},
    "brower": {"likely_cn_articles": [], "top_results": [], "fallback_results": []},
    "wechat": {"articles": []}
  }
}
```

## Automation

GitHub Actions are included:

- `CI` (`.github/workflows/main.yml`): runs `main.py` hourly.
- `LLM` (`.github/workflows/llm.yml`): runs `LLM.py` every 2 days.

## Disclaimer

This project is for security monitoring, research, and defense use. Validate all findings before operational use.
