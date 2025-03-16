import requests
import os
import time
import datetime
import multiprocessing
import json
from hashlib import md5
from urllib.parse import urlencode
from loguru import logger
import sys

# 配置loguru
logger.add(
    "logs/{time:YYYY-MM-DD}.log",  # 日志文件路径，按日期+用户名命名
    rotation="00:00",  # 每天零点创建新文件
    retention="7 days",  # 保留7天的日志
    encoding="utf-8",
    enqueue=True,  # 启用队列模式，支持多进程
    format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} |{extra[username]} - {name}:{line} - {message}",  # 添加username列
)

HEADER = {
    'accept': 'application/json, text/plain, */*',
    'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7',
    'content-type': 'application/json;charset=UTF-8',
    'origin': 'https://www.leigod.com',
    'priority': 'u=1, i',
    'referer': 'https://www.leigod.com/',
    'sec-ch-ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
}
KEY = "5C5A639C20665313622F51E93E3F2783"

class LeiGod:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.token_file = f'{self.username}_token.txt'
        self.logger = logger.bind(username=username)
        
    def md5(self, str):
        return md5(str.encode("utf-8")).hexdigest()
        
    def get_token(self):
        # 检查token文件是否存在
        if os.path.exists(self.token_file):
            try:
                # 从文件中读取token
                with open(self.token_file, 'r') as f:
                    token = f.read().strip()
                    if token:
                        # 验证token有效性
                        if self.ckeck_token(token):
                            self.logger.info(f"读取缓存Token成功")
                            return token
                        else:
                            self.logger.warning("Token已失效，需要重新登录获取")
            except Exception as e:
                self.logger.error(f"读取token文件失败: {e}")
        
        # 如果文件不存在或读取失败或token无效，则调用login获取新token
        self.logger.info("登录获取token")
        token = self.login()
        # 将新token保存到文件
        try:
            with open(self.token_file, 'w') as f:
                f.write(token)
        except Exception as e:
            self.logger.error(f"保存token到文件失败: {e}")
            
        return token

    def login(self):
        # 构建请求参数
        bodyToSign = {
            "account_token": "null",
            "country_code": 86,
            "lang": "zh_CN",
            "mobile_num": self.username,
            "os_type": 4,
            "password": self.md5(self.password),
            "region_code": 1,
            "src_channel": "guanwang",
            "username": self.username,
        }
        
        # 添加时间戳和签名
        bodyToSign["ts"] = int(time.time())
        str_to_sign = urlencode(sorted(bodyToSign.items())) + '&key=' + KEY
        bodyToSign["sign"] = self.md5(str_to_sign)

        response = requests.post(
            "https://webapi.leigod.com/api/auth/login/v1",
            json=bodyToSign,
            headers=HEADER,
        ).json()

        if response['code'] == 0:
            return response['data']['login_info']['account_token']

        self.logger.error(f"登录失败: {response}")
        raise Exception(response)
    
    def ckeck_token(self, token):
        palyload = {
            "account_token": token,
            "lang": "zh_CN",
            "os_type": 4,
        }

        response = requests.post('https://webapi.leigod.com/api/user/info', headers=HEADER, json=palyload).json()
        if response['code'] == 0:
            return True
        else:
            return False
    
    def pause(self):
        token = self.get_token()

        payload = {
            "account_token": token,
            "lang": "zh_CN",
            "os_type": 4,
        }
        msg = requests.post('https://webapi.leigod.com/api/user/pause', json=payload, headers=HEADER).json()
        if msg['code'] != 0:
            self.logger.error(f"暂停失败: {msg}")
            raise Exception(msg)
        self.logger.success("暂停成功")
    
    def log(self):
        # 获取token
        token = self.get_token()
        
        palyload = {
            'account_token': token,
            'page': 1,
            'size': 1,
            'lang': 'zh_CN',
            'region_code': 1,
            'src_channel': 'guanwang',
            'os_type': 4,
        }

        response = requests.post('https://webapi.leigod.com/api/user/time/log', headers=HEADER, json=palyload).json()
        if response['code'] == 0 and response['data']['list']:
            data = response['data']['list'][0]
            # {
            #     "create_time": "2025-03-10 20:21:58",
            #     "update_time": null,
            #     "recover_time": "2025-03-10 20:21:58",
            #     "pause_time": null,
            #     "pause_surplus_time": null,
            #     "recover_surplus_time": 19463,
            #     "recover_expire_time": "2025-03-11 01:46:21",
            #     "reduce_pause_time": 0,
            #     "reduce_expired_time": 0,
            #     "recover_experience_expired_time": "2023-09-16 00:04:30",
            # }
            return data
        self.logger.error(f"获取日志失败: {response}")
        raise Exception(response)
    
    def check_and_auto_pause(self):
        """检查加速状态并根据条件自动暂停"""
        log_data = self.log()
        self.logger.debug(f"当前加速状态: {log_data}")

        if log_data.get('recover_tag') == '活动时长自动开启':
            self.logger.info("活动时长自动开启，无需暂停")
            return
        
        # 检查是否正在加速中（没有暂停时间表示正在加速）
        if log_data.get('pause_time') is not None:
            self.logger.info("当前未在加速状态，无需暂停")
            return
        
        # 获取当前时间
        now = datetime.datetime.now()
        current_hour = now.hour
        
        # 解析加速开始时间
        try:
            recover_time = datetime.datetime.strptime(log_data.get('recover_time'), "%Y-%m-%d %H:%M:%S")
            # 计算已加速时间（小时）
            total_seconds = (now - recover_time).total_seconds()
            acceleration_hours = int(total_seconds // 3600)
            acceleration_minutes = int((total_seconds % 3600) // 60)
            acceleration_seconds = int(total_seconds % 60)
            self.logger.info(f"已加速时间: {acceleration_hours}h {acceleration_minutes}m {acceleration_seconds}s")
            
            # 判断条件：
            # 1. 如果加速开始时间在19-24点之间，且当前时间已过凌晨1点，且日期已经是第二天，则暂停
            recover_hour = recover_time.hour
            # 判断是否是第二天
            is_next_day = now.date() > recover_time.date()
            if 19 <= recover_hour <= 23 and is_next_day:
                self.logger.success("满足自动暂停条件：晚间开始加速且已过第二天凌晨")
                self.pause()
                return
                        
            # 额外条件：如果加速时间超过6小时，无论什么时间都暂停
            if total_seconds >= 3600 * 6:  # 6小时
                self.logger.success(f"满足自动暂停条件：加速时间超过6小时")
                self.pause()
                return

        except Exception as e:
            self.logger.error(f"解析加速时间出错: {e}")
            return

    def run_auto_pause_daemon(self):
        """运行自动暂停守护进程
        Args:
            check_interval: 检查间隔
        """
        check_interval = 60 * 10
        self.logger.info(f"启动账号 {self.username} 的自动暂停守护进程")
        try:
            while True:
                self.check_and_auto_pause()
                time.sleep(check_interval)
        except KeyboardInterrupt:
            self.logger.warning("自动暂停守护进程已停止")
        except Exception as e:
            self.logger.error(f"自动暂停守护进程出错: {e}")


def run_daemon(username, password):
    """独立的运行函数，作为进程目标
    Args:
        username: 用户名
        password: 密码
    """
    # 创建LeiGod实例并运行守护进程
    leigod = LeiGod(username, password)
    leigod.run_auto_pause_daemon()

if __name__ == '__main__':
    import json
    # 使用with语句安全打开文件
    with open('config.json', 'r') as f:
        account = json.load(f)

    processes = []
    for i in account:
        p = multiprocessing.Process(target=run_daemon, args=(i['username'], i['password']))
        processes.append(p)
        p.start()
    
    for p in processes:
        p.join()
