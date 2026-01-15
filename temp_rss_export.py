#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 临时脚本：将 The Hacker News RSS 导出到 JSON

import feedparser
import requests
import json

feed_url = "https://www.thehackerwire.com/feed"

response = requests.get(feed_url, timeout=30)
response.encoding = 'utf-8'
feed = feedparser.parse(response.text)

entries = []
for entry in feed.entries:
    entries.append({
        'title': entry.title,
        'summary': entry.get('summary', ''),
        'link': entry.link,
        'published': entry.get('published', '')
    })

with open('./RSSs/thehackerwire.json', 'w', encoding='utf-8') as f:
    json.dump(entries, f, ensure_ascii=False, indent=4)

print(f"导出完成，共 {len(entries)} 条记录到 ./RSSs/thehackersnews.json")