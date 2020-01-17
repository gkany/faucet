# -*- coding:utf-8 -*-

#权限验证参数
auth_list = {
    'origon': 'YnVmZW5nQDIwMThidWZlbmc='
}

#命令行钱包地址
# cli_wallet_url = "http://127.0.0.1:8048"
cli_wallet_url = "http://172.17.25.178:8048"

#请求头
headers = {"content-type": "application/json"}

# testnet | prod
env = "prod"
g_hostname = "localhost"
g_ip = "127.0.0.1"

#注册帐户的注册人
# faucet1 1.2.18 faucet2 1.2.19 faucet3 1.2.20 faucet4 1.2.21
register = "faucet1"
register_id = "1.2.18"

#mysql数据库相关参数
db = {
    'host': 'xxxx',
    'port': 3306,
    'user': 'faucet',
    'password': 'xxxx',
    'charset': 'utf8',
    'db': 'CocosBCX'
}

tables = { 
    'users': 'cocosUsers'
}

#数据库操作相关语句
sql = {
    'createTable': 'CREATE TABLE IF NOT EXISTS ' + tables['users'] + ' (id char(10), name varchar(32), pubkey char(128), ip char(32), create_time char(32), status TINYINT default 0, register varchar(32) DEFAULT NULL)default charset=utf8',
    'insertData': "INSERT INTO " + tables['users'] + " (id, name, pubkey, ip, create_time, register) VALUES('{}','{}','{}','{}','{}','{}')"
}

#核心资产
asset_core = 'COCOS'
asset_core_precision = 5

#Gas
asset_gas = 'GAS'
gas_core_exchange_rate = 1

#发送奖励数量
# testnet临时测试 100000
reward_core = 0.1 
reward_core_until_N = 1000
transfer_operation_N = 2
#reward_gas = reward_core * (10 ** asset_core_precision) * gas_core_exchange_rate * transfer_operation_N
reward_gas = 20000

#注册完成欢迎信息
memo = 'Welcome To COCOS Community!'

#每天创建账户最大数
has_account_max_limit = True
registrar_account_max = 10000

# ip 限制(每天)
has_ip_max_limit = True 
ip_max_register_limit = 20

#ip 黑名单
ip_limit_list = set()
#ip_limit_list.add("127.0.0.1")

# dingding
access_token = "xxxx"
faucet_alert_address = "https://oapi.dingtalk.com/robot/send?access_token=" + access_token