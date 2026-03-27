import yaml
import logging
import json
import requests
from hashlib import md5
import random
import os

baidu_appid = os.environ.get("baidu_appid")
baidu_appkey = os.environ.get("baidu_appkey")

 #读取配置文件
def load_config():
    with open('./utils/config.yaml', 'r', encoding='utf-8') as f:
        config = yaml.load(f,Loader=yaml.FullLoader)
        #github_token = config['all_config']['github_token']
        if int(config['all_config']['wechat'][0]['enable']) == 1:
            webhook = config['all_config']['wechat'][1]['webhook']
            app_name = config['all_config']['wechat'][3]['app_name']
            return app_name,webhook
        elif int(config['all_config']['tgbot'][0]['enable']) ==1 :
            tgbot_token = config['all_config']['tgbot'][1]['token']
            tgbot_group_id = config['all_config']['tgbot'][2]['group_id']
            app_name = config['all_config']['tgbot'][3]['app_name']
            return app_name,tgbot_token,tgbot_group_id
        elif int(config['all_config']['tgbot'][0]['enable']) == 0 and int(config['all_config']['feishu'][0]['enable']) == 0 and int(config['all_config']['server'][0]['enable']) == 0 and int(config['all_config']['pushplus'][0]['enable']) == 0 and int(config['all_config']['dingding'][0]['enable']) == 0:
            logging.error("[-] 配置文件有误, 社交软件的enable不能为0")

def load_tools_list():
    with open('./utils/monitor_list.yaml', 'r',  encoding='utf-8') as f:
        list = yaml.load(f,Loader=yaml.FullLoader)
        return list['repo_list'], list['keyword_list'], list['user_list']


def load_wechat_sources():
    # Load the configured WeChat publisher names monitored through the wxvl archive.
    with open('./utils/monitor_list.yaml', 'r', encoding='utf-8') as f:
        data = yaml.load(f, Loader=yaml.FullLoader) or {}
        return data.get('wechat_sources', [])
    
def load_clean_list():
    with open('./utils/clean.yaml', 'r',  encoding='utf-8') as f:
        list = yaml.load(f,Loader=yaml.FullLoader)
        return list['clean_list']
    
def load_object_list():
    with open('./utils/known_object.yaml', 'r',  encoding='utf-8') as f:
        list = yaml.load(f,Loader=yaml.FullLoader)
        return list['object']
    
def flash_clean_list(new_items):
    new_items = list(set(new_items))
    # 读取现有数据
    try:
        with open("./utils/clean.yaml", "r", encoding="utf-8") as file:
            existing_data = yaml.safe_load(file) or {}
    except FileNotFoundError:
        existing_data = {}

    # 获取现有 clean_list（如果不存在则初始化空列表）
    existing_clean_list = existing_data.get("clean_list", [])

    # 追加新条目到现有列表（假设 new_items 是一个列表）
    existing_clean_list.extend(new_items)

    # 更新数据
    existing_data["clean_list"] = existing_clean_list

    # 写回文件（覆盖模式）
    with open("./utils/clean.yaml", "w", encoding="utf-8") as file:
        yaml.dump(existing_data, file, default_flow_style=False)

def json_data_load(file_path):
    with open(file_path,encoding="UTF-8") as f:
        json_data = json.load(f)
    return json_data

def json_data_save(file,entries):
    with open(file, 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False, indent=4)

def baidu_api(query):

    # For list of language codes, please refer to `https://api.fanyi.baidu.com/doc/21`
    from_lang = 'zh'
    to_lang =  'en'

    endpoint = 'http://api.fanyi.baidu.com'
    path = '/api/trans/vip/translate'
    url = endpoint + path

    # Generate salt and sign
    def make_md5(s, encoding='utf-8'):
        return md5(s.encode(encoding)).hexdigest()

    salt = random.randint(32768, 65536)
    sign = make_md5(baidu_appid + query + str(salt) + baidu_appkey)

    # Build request
    header = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {'appid': baidu_appid, 'q': query, 'from': to_lang, 'to': from_lang, 'salt': salt, 'sign': sign}

    # Send request
    r = requests.post(url, params=payload, headers=header)
    result = r.json()
    dst_string = result["trans_result"][0]["dst"]
   
    # Show response
    return dst_string.rstrip()
