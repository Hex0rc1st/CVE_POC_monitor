[English README](./README.md)

# CVE_POC_monitor

CVE_POC_monitor 是一个自动化漏洞情报监控项目，用于聚合高价值 CVE/PoC 信息，并将告警推送到消息渠道与 Google Sheets。

## 项目功能

- 轮询多个漏洞/安全情报 RSS 源，发现新增高风险条目后自动推送。
- 按 CVE 关键词（如 `CVE-2024-`、`CVE-2025-`、`CVE-2026-`）检索新建 GitHub 仓库，快速发现公开 PoC。
- 监控指定 GitHub 仓库目录中的新增 PoC 文件。
- 拉取 CISA KEV（Known Exploited Vulnerabilities）CSV，增量推送新收录 CVE。
- 监控 GitHub Advisory Database 的最新提交，解析新增 advisory JSON。
- 可选执行 `LLM.py`，对原始 PoC 脚本进行请求包线索提取。

## 项目引用的数据来源

### 1）官方/API 数据

- **GitHub Search API**：按关键词检索仓库。
- **GitHub Commits/Contents API**：监控提交与文件变更。
- **GitHub Advisory 原始 JSON**：提取别名、严重等级、详情等字段。
- **CISA KEV CSV**：  
  `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv`
- **Google Apps Script Webhook**（用户自建）：用于写入/读取监控数据（如 `CVE`、`raw`、`Emergency Vulnerability`）。

### 2）本地状态与规则数据

- `utils/monitor_list.yaml`：关键词列表与重点仓库目录。
- `utils/clean.yaml`：去重/过滤列表（已处理项目名）。
- `utils/known_object.yaml`：重点组件关键词（用于 advisory 过滤）。
- `utils/CISA.txt`：已推送 CISA CVE 记录。
- `utils/sha.txt`：已处理 GitHub 提交 SHA 记录。
- `RSSs/*.json`：已拉取 RSS 条目的本地快照（用于去重）。

## RSS 源清单（以 `RSSs/rss_config.json` 为准）

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

## 推送与存储目标

- Telegram（`tg_token`、`tg_chat_id`）
- 企业微信/微信机器人（`wechat_token`）
- Google Sheets（`google_sheet_token`）

## 快速开始

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

可选 LLM 分析：

```bash
export llm_url="..."
export llm_api_key="..."
python3 LLM.py
```

## 自动化运行

仓库内已包含 GitHub Actions：

- `CI`（`.github/workflows/main.yml`）：每小时执行 `main.py`
- `LLM`（`.github/workflows/llm.yml`）：每 2 天执行一次 `LLM.py`

## 免责声明

本项目用于安全监测、研究与防御场景。请在生产使用前自行验证数据准确性与处置流程。
