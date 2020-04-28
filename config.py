# -*- coding:utf-8 -*-

auth_list = {
    'origon': 'YnVmZW5nQDIwMThidWZlbmc='
}

sdk_config = {
    "node_address": "ws://127.0.0.1:8049",
    "wallet_password": "123456",
}

register = {
    "name": "nicotest",
    "id": "1.2.16",
    "private_key": "5J2SChqa9QxrCkdMor9VC2k9NT4R4ctRrJA6odQCPkb3yL89vxo",
    "public_key": "COCOS56a5dTnfGpuPoWACnYj65dahcXMpTrNQkV3hHWCFkLxMF5mXpx",
}

headers = {"content-type": "application/json"}

env_config = {
    "env": "prod", # testnet | prod, docker use
    "hostname": "localhost",
    "ip": "127.0.0.1"
}

db_config = {
    'pool_name': 'faucet',
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '123456',
    'database': 'cocosbcx'
}

asset_config = {
    "core_asset": {
        "symbol": "COCOS",
        "precision": 5
    },
    "gas_asset": {
        "symbol": "GAS",
        "precision": 5,
        "exchange_rate": 1
    }
}

reward_config = {
    "core_asset": {
        "amount": 0.1,
    },
    "gas_asset": {
        "amount": 20000,    # 0.2 GAS; default reward gas
        "NTransfer": 6,     # reward_gas = NTransfer * exchange_rate * transfer_base_fee
    }
}

limit_config = {
    "address_max": {
        "name": "address_max",
        "enable": True,
        "amount": 200
    },
    "daily_max": {
        "name": "daily_max",
        "enable": True,
        "amount": 10000
    },
    "blacklist": {
        "name": "blacklist",
        "enable": False,
        "ips": ["127.0.0.1"]
    }
}

#defaut transfer memo
default_memo = 'Welcome To COCOS Community!'

access_token = "ddf5792a6a4ddc5117026dfc7f90b14e22584b7ecf72a66f4ddf45506fa076f7"
alert_address = "https://oapi.dingtalk.com/robot/send?access_token=" + access_token
