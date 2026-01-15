#!/usr/bin/env python 
# -*- coding: utf-8 -*-
# @Time    : 2025/03/04
# @Author  : LXY
# @File    : main.py
# @Github: https://github.com/MMarch7
import datetime
import feedparser
import logging
import os
#import dingtalkchatbot.chatbot as cb
import requests
import re
import utils.load
from urllib.parse import quote
import msg_push
import csv

github_token = os.environ.get("github_token")
repo_list,keywords,user_list = utils.load.load_tools_list()
CleanKeywords = utils.load.load_clean_list()
known_object = utils.load.load_object_list()
github_sha = "./utils/sha.txt"

def load_processed_shas():
    if not os.path.exists(github_sha):
        return set()
    with open(github_sha, 'r') as f:
        return {line.strip() for line in f if line.strip()}

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

def parse_rss_feed(feed_url,file):
    # 解析RSS feed
    try:
        response = requests.get(feed_url,timeout=20)
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
        logging.warning(f"{file} 解析RSS feed时发生错误: {feed.bozo_exception}")
        return
    all_entries = utils.load.json_data_load(f"./RSSs/{file}")
    existing_titles = {entry['link'] for entry in all_entries}
    # 定义一个标志，标记是否输出了新增条目
    new_entries_found = False
    for entry in feed.entries:
        if entry.link not in existing_titles:
            # 输出新增条目
            new_entries_found = True
            all_content_have_cve = True
            logging.info(f"标题: {entry.title}  链接: {entry.link}")
            logging.info("-" * 40)
            if file == "google.json":
                if 'cve' not in str(entry.content).lower():
                    all_content_have_cve = False  # 如果发现某个 content 没有 "CVE"，标记为 False
                    break 
            if file == "vulncheck.json" or file == "securityonline.json" or file == "picus.json" or file == "rapid7.json" or file == "thehackersnews.json":
                if "cve" not in entry.title.lower() and "vulnerabili" not in entry.title.lower():
                    all_content_have_cve = False  # 如果发现某个 content 没有 "CVE"，标记为 False
            if file == "zerodayinitiative.json":
                if ("cve" not in entry.title.lower() and "vulnerabili" not in entry.title.lower()) and "Security Update Review" not in entry.title:
                    all_content_have_cve = False  # 如果发现某个 content 没有 "CVE"，标记为 False
            if file == "paloalto.json":
                if "medium" in entry.title.lower() or "low" in entry.title.lower():
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
                    'title': entry.title,
                    'link': entry.link,
                    'published': entry.published
                })
            # 将新增条目添加到新条目列表
            if all_content_have_cve:
                # 检查是否存在历史PoC
                poc_prefix = ""
                cve_ids = extract_cve_ids(entry.title)
                for cve_id in cve_ids:
                    poc_links = check_cve_in_poc_history(cve_id)
                    if poc_links:
                        poc_prefix = f"该漏洞疑似存在poc批量：「{poc_links[0]}」\r\r"
                        logging.info(f"发现历史PoC: {cve_id} -> {poc_links[0]}")
                        break  # 找到一个就够了
                
                msg = f"{poc_prefix}标题：{entry.title}\r链接：{entry.link}\r发布时间：{entry.published}"
                logging.info(f"推送到google sheet：{entry.title}  "+entry.link)
                msg_push.wechat_push(msg)
                msg_push.send_google_sheet_githubVul("Emergency Vulnerability","RSS",entry.title,"",entry.link,"")
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

def save_file_locally(url, filename):
    try:
        response = requests.get(url,headers=github_headers)
    except Exception as e:
        logging.info(f"An unexpected error occurred: {e}")
    if response.status_code == 200:
        data = response.json()
        aliases = data.get('aliases', [])
        aliases_str = ', '.join(aliases)
        details = data.get('details', '')
        severity = data.get('database_specific', '').get('severity', '')
        for item in known_object:
            if item in details.lower() and severity in ["HIGH","CRITICAL","Unknown","MODERATE"]:
                if item == "jenkins":
                    if "plugin" in details.lower() and "core" not in details.lower():
                        break
                url = f"https://github.com/advisories/{data.get('id', '')}"
                detail = utils.load.baidu_api(details)
                msg = f"编号：{aliases_str}\r\n组件：{item}\r\n信息：{detail}\r\n链接：{url}"
                logging.info(f"企微推送：{aliases_str}  "+url)
                msg_push.wechat_push(msg)
                msg_push.send_google_sheet_githubVul("Emergency Vulnerability","github",item,aliases_str,url,detail)
                msg_push.tg_push(msg)
                break
    else:
        logging.info(f"Failed to read {filename}: {response.status_code}")


def getGithubVun():
    url = f"https://api.github.com/repos/github/advisory-database/commits"
    try:
        response = requests.get(url,headers=github_headers)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}") 
    if response.status_code == 200:
        latest_commit = response.json()[0]
        commit_message = latest_commit['commit']['message']
        commit_url = latest_commit['html_url']
        commit_sha = latest_commit['sha']
        if not os.path.exists(github_sha):
            open(github_sha, 'w').close()
        with open(github_sha, 'r') as file:
            lines = file.readlines()
            # 如果a在文件中，则结束函数
            if str(commit_sha) + '\n' in lines:
                logging.info("没有新的commit被提交")
                return
        with open(github_sha, 'a') as file:
            file.write(str(commit_sha) + '\n')
        logging.info(f"Latest commit message: {commit_message}")
        logging.info(f"Commit URL: {commit_url}")
        # 获取详细修改内容
        commit_details_url = f"https://api.github.com/repos/github/advisory-database/commits/{commit_sha}"
        details_response = requests.get(commit_details_url,headers=github_headers)
        if details_response.status_code == 200:
            commit_details = details_response.json()
            files_changed = commit_details.get('files', [])
            #logging.info("\nFiles changed:")
            for file in files_changed:
                filename = file['filename']
                #additions = file['additions']
                #deletions = file['deletions']
                #changes = file['changes']
                status = file['status']
                if filename.endswith('.json') and status == "added":
                    # 构建原始文件的 URL
                    raw_url = f"https://raw.githubusercontent.com/github/advisory-database/{commit_sha}/{filename}"
                    save_file_locally(raw_url, filename)
                    logging.info(f"- {filename}: {status} ")
        else:
            logging.info(f"Failed to retrieve commit details: {details_response.status_code}")
            
# 获取最近一次提交的变更文件
def get_latest_commit_files(repo,branch):
    try:
        processed_shas = load_processed_shas()
        # 分页获取新提交
        page = 1
        max_pages = 2  # 新增：最多获取2页
        per_page = 100
        new_shas = []
        # 获取最新提交（指定分支）
        while page <= max_pages:  # 修改循环条件
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
                    # 遇到已处理 SHA，停止遍历
                    break
                new_shas.append(sha)
            # 如果当前页有已处理 SHA，停止翻页
            if any(sha in processed_shas for sha in new_shas):
                break
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
        with open(github_sha, 'a') as f:
            for sha in new_shas:
                f.write(f"{sha}\n")
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
        msg_push.tg_push(f"{repo}项目新增PoC推送:\r\n名称：{file_path}\r\n地址：{url}")
        msg_push.send_google_sheet("CVE",repo,file_path,url,"")
        logging.info(f"✅ 获取文件内容成功: {file_path} ")
    except requests.RequestException as e:
        logging.error(f"❌ 获取文件内容失败: {file_path} -> {e}")

def getRepoPoCs():
    for repo in repo_list:
        repo_name = repo["name"]
        folder = repo["folder"].rstrip('/') + '/'  # 规范目录格式
        branch = repo.get("branch", "main")
        changed_files = get_latest_commit_files(repo_name, branch)
        if changed_files is None:
            logging.error(f"❌ 获取 {repo_name} 的变更文件失败，已跳过")
            continue  # 错误已记录，跳过处理
        new_files = list({file for file in changed_files if file.startswith(folder)})
        if new_files:
            logging.info(f"📦 {repo_name} 发现 {len(new_files)} 个新文件:")
            for idx, file in enumerate(new_files, 1):
                logging.info(f"  {idx}. {file}")
            for file in new_files:
                read_file(repo_name, branch, file)
        else:
            logging.info(f"✅ {repo_name} 的 {folder} 目录无新文件变更")

def main():
    init()
    #紧急漏洞RSS推送
    logging.info("----------------------------------------------------------")
    logging.info("----------------------紧急漏洞RSS推送-----------------------")
    logging.info("----------------------------------------------------------")
    getRSSNews()
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
