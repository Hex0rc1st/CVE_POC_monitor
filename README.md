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

## Automation

GitHub Actions are included:

- `CI` (`.github/workflows/main.yml`): runs `main.py` hourly.
- `LLM` (`.github/workflows/llm.yml`): runs `LLM.py` every 2 days.

## Disclaimer

This project is for security monitoring, research, and defense use. Validate all findings before operational use.
