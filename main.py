import requests
import os
import time
import datetime
from hashlib import md5
from urllib.parse import urlencode

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
                        print(f"从文件{self.token_file}中读取token成功")
                        # 验证token有效性
                        if self.ckeck_token(token):
                            print("Token验证有效")
                            return token
                        else:
                            print("Token已失效，需要重新登录获取")
            except Exception as e:
                print(f"读取token文件失败: {e}")
        
        # 如果文件不存在或读取失败或token无效，则调用login获取新token
        print("需要重新登录获取token")
        token = self.login()
        
        # 将新token保存到文件
        try:
            with open(self.token_file, 'w') as f:
                f.write(token)
            print(f"token已保存到文件{self.token_file}")
        except Exception as e:
            print(f"保存token到文件失败: {e}")
            
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
            raise Exception(msg)
        print("暂停成功")
    
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
        raise Exception(response)
    
    def check_and_auto_pause(self):
        """检查加速状态并根据条件自动暂停"""
        log_data = self.log()
        print(f"当前加速状态: {log_data}")
        
        # 检查是否正在加速中（没有暂停时间表示正在加速）
        if log_data.get('pause_time') is not None:
            print("当前未在加速状态，无需暂停")
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
            print(f"已加速时间: {acceleration_hours}h {acceleration_minutes}m {acceleration_seconds}s")
            
            # 判断条件：
            # 1. 加速时间超过5小时
            # 2. 当前不是晚上6点到凌晨1点的高峰使用时段
            if acceleration_hours >= 5 and not (18 <= current_hour or current_hour <= 1):
                print("满足自动暂停条件：加速时间超过6小时且不在晚间高峰期")
                self.pause()
                return 
            
            # 额外条件：如果加速时间超过12小时，无论什么时间都暂停
            if acceleration_hours >= 12:
                print("满足自动暂停条件：加速时间超过12小时")
                self.pause()
                return

        except Exception as e:
            print(f"解析加速时间出错: {e}")
            return False

    def run_auto_pause_daemon(self):
        """运行自动暂停守护进程
        Args:
            check_interval: 检查间隔，单位秒，默认1分钟
        """
        check_interval = 60 
        try:
            while True:
                print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 执行自动暂停检查...")
                self.check_and_auto_pause()
                time.sleep(check_interval)
        except KeyboardInterrupt:
            print("\n自动暂停守护进程已停止")
        except Exception as e:
            print(f"自动暂停守护进程出错: {e}")


if __name__ == '__main__':
    import json
    account = json.load(open('config.json', 'r'))

    for i in account:
        t = LeiGod(i['username'], i['password'])
        t.run_auto_pause_daemon()
