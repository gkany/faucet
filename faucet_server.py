# -*- coding:utf-8 -*-

import os
import json
import random
import pymysql
import requests
import datetime
import time
import socket

import tornado.ioloop
import tornado.web
import tornado.httpserver

from threading import Thread
from tornado.options import define, options, parse_command_line
from config import *
from utils import *

logger = Logging().getLogger()

# 定义默认端口
define('port', default=8041, type=int)

def init_reward():
    global asset_core_precision
    global core_exchange_rate
    global reward_gas
    global gas_core_exchange_rate
    global register_id

    try:
        #get_global_properties --> transfer_fee
        body_relay = {
            "jsonrpc": "2.0",
            "method": "get_global_properties",
            "params": [],
            "id":1
        }
        properties = json.loads(requests.post(cli_wallet_url, data = json.dumps(body_relay), headers = headers).text)['result']
        transfer = properties['parameters']['current_fees']['parameters'][0]
        if transfer[0] == 0:
            #get_asset COCOS --> asset_core_precision
            body_relay = {
                "jsonrpc": "2.0",
                "method": "get_asset",
                "params": [asset_core],
                "id":1
            }
            asset = json.loads(requests.post(cli_wallet_url, data = json.dumps(body_relay), headers = headers).text)['result']
            logger.info('core asset: {}'.format(asset))
            asset_core_precision = asset['precision']

            #get_asset GAS --> core_exchange_rate
            body_relay = {
                "jsonrpc": "2.0",
                "method": "get_asset",
                "params": [asset_gas],
                "id":1
            }
            asset = json.loads(requests.post(cli_wallet_url, data = json.dumps(body_relay), headers = headers).text)['result']
            logger.info('gas asset: {}'.format(asset))
            core_exchange_rate = asset['options']['core_exchange_rate']
            gas_core_exchange_rate = round(core_exchange_rate['quote']['amount']/core_exchange_rate['base']['amount'])
            #reward_core = int(transfer[1]['fee']/(10**asset_core_precision) * transfer_operation_N)
            reward_gas = transfer[1]['fee'] * gas_core_exchange_rate * transfer_operation_N

            # init register account_id
            register_id = get_account(register)["id"]
            logger.info('register: {}, register_id: {}, gas_core_exchange_rate: {}, reward_gas: {}, reward_core: {}, transfer fee: {}'.format(
                register, register_id, gas_core_exchange_rate, reward_gas, reward_core, transfer))
    except Exception as e:
        logger.error('init failed. error: {}'.format(repr(e)))
        push_message("init reward error")

def init_db():
    my_db = pymysql.connect(**db)   #连接数据库并创建表
    cursor = my_db.cursor()
    try:
        cursor.execute(sql["createTable"])
        my_db.commit()
    except Exception as e:
        my_db.rollback()
        logger.warn('init failed. error: {}'.format(repr(e)))
        # push_message("init db error")
    my_db.close()

def init_host_info():
    global g_hostname
    global g_ip
    try:
        g_hostname = socket.getfqdn(socket.gethostname())
        g_ip = socket.gethostbyname(g_hostname)
    except Exception as e:
        logger.warn('init host info. error: {}'.format(repr(e)))
    if 'HOST_NAME' in os.environ:
        g_hostname = os.environ['HOST_NAME']  
    logger.info('hostname: {}, ip: {}'.format(g_hostname, g_ip))

#服务启动初始化
def initialize():
    init_host_info()
    init_db()
    init_reward()
    logger.info('ip_limit_list: {}'.format(ip_limit_list))
    logger.info('init done.')

def push_message(message, labels=['faucet']):
    content = "[{}]{} {}, {}".format(env, str(labels), g_hostname, message)
    logger.debug('push content: {}'.format(content))
    return    # no need

    try:
        body_relay = {
            "jsonrpc": "2.0",
            "msgtype": "text",
            "text": {
                "content": content
            },
            "id":1
        }
        json.loads(requests.post(faucet_alert_address, data = json.dumps(body_relay), headers = headers).text)
    except Exception as e:
        logger.error('push error. {}'.format(repr(e)))

def get_account_asset_balance(account):
    asset_balances = {}
    try:
        body_relay = {
            "jsonrpc": "2.0",
            "method": "list_account_balances",
            "params": [account],
            "id":1
        }
        response = json.loads(requests.post(cli_wallet_url, data = json.dumps(body_relay), headers = headers).text)
        balances = response['result']
        logger.debug('account {} balance {}'.format(account, balances))
        for ab in balances:
            asset_balances[ab['asset_id']] = int(ab['amount'])
    except Exception as e:
        logger.error('get {} balance error. {}'.format(account, repr(e)))
    return asset_balances

def params_valid(account):
    logger.info('account: {}'.format(account)) 
    name = account.get('name', '') #获取帐户名
    active_key = account.get('active_key', '') #获取active公钥
    owner_key = account.get('owner_key', '')   #获取owner公钥
    if not name:
        return False, response_dict['bad_request'], {}
    if not is_cheap_name(name):
        return False, response_dict['not_cheap_account'], {}
    if not active_key:
        return False, response_dict['bad_request'], {}
    if not owner_key:
        owner_key = active_key  
    if not is_valid_name(name):
        msg = response_module(response_dict['bad_request']['code'], msg="account {} illegal".format(name))
        return False, msg, {}
    return True, '', {'name': name, 'active_key': active_key, 'owner_key': owner_key}

def send_reward_transfer(balances, account_name, memo=memo):
    core_asset_id = "1.3.0"
    if core_asset_id not in balances:
        return False

    try: 
        core_amount = balances[core_asset_id]
        if reward_core*(10**asset_core_precision) < core_amount:
            body_relay = {
                "jsonrpc": "2.0",
                "method": "transfer",
                "params": [register, account_name, "%.5f"%(reward_core), asset_core, [memo, "false"], "true"],
                "id":1
            }
            response = json.loads(requests.post(cli_wallet_url, data = json.dumps(body_relay), headers = headers).text)
            if 'error' not in response:
                return True
            else:
                message = '{} {} failed. error: {}'.format(body_relay['method'], body_relay['params'], response["error"])
                logger.warn(message)
        else:
            message = 'register {} no enough {}({}), reward need {}'.format(
                register, asset_core, core_amount/(10**asset_core_precision), reward_core)
            logger.warn(message)
    except Exception as e:
        message = 'register {} no {}, reward need {}'.format(register, asset_core, reward_core)
        logger.error('{}, error: {}'.format(message, repr(e)))
    return False

def send_reward_gas(balances, account_id):
    gas_asset_id = "1.3.1"
    if gas_asset_id not in balances:
        return False

    try:
        gas_amount = balances[gas_asset_id]
        if reward_gas < gas_amount:
            body_relay = {
                "jsonrpc": "2.0",
                "method": "update_collateral_for_gas",
                "params": [register_id, account_id, int(reward_gas), "true"],
                "id":1
            }
            response = json.loads(requests.post(cli_wallet_url, data = json.dumps(body_relay), headers = headers).text)
            if 'error' not in response:
                return True
            else:
                message = '{} {} failed. error: {}'.format(body_relay['method'], body_relay['params'], response["error"])
                logger.warn(message)
        else:
            message = 'register {} no enough {}({}), collateral need {}'.format(
                register, asset_gas, gas_amount/(10**asset_core_precision), reward_gas/(10**asset_core_precision))
            logger.warn(message)
    except Exception as e:
        message = 'register {} no {}, reward need {}'.format(register, asset_gas, reward_gas/(10**asset_core_precision))
        logger.error('{}, error: {}'.format(message, repr(e)))
    return False

def send_reward(core_count, account_id, account_name):
    balances = get_account_asset_balance(register)
    logger.info('core_count:{}, account_id: {}, register {} balance: {}, reward_core: {}, reward_gas: {}'.format(
        core_count, account_id, register, balances, reward_core, reward_gas))

    if not balances:
        return -1 # 不计算失败次数

    if core_count < reward_core_until_N:
        transfer_status = send_reward_transfer(balances, account_name)
    else:
        transfer_status = False
    
    collateral_status = send_reward_gas(balances, account_id)
    if transfer_status or collateral_status:
        return 0  # 成功
    else:
        return 1  # 失败

#注册帐户
def register_account(account):
    try:    
        body_relay = {
            "jsonrpc": "2.0",
            "method": "register_account",
            "params": [account['name'], account['owner_key'], account['active_key'], register, "true"],
            "id":1
        }
        response = requests.post(cli_wallet_url, data = json.dumps(body_relay), headers = headers).text
        info = json.loads(response)
        if "error" in info:
            error = info["error"]["message"]
            logger.info('request: {}, error: {}'.format(body_relay, error))
            if error.find('current_account_itr == acnt_indx') != -1:
                return False, response_dict['account_registered'], '' #账号名已存在
            elif error.find('is_valid_name') != -1: #非法的账户名
                msg = response_module(response_dict['bad_request']['code'], msg="account {} illegal".format(account['name']))
                return False, msg, ''
            elif error.find('skip_transaction_dupe_check') != -1: #操作太频繁
                msg = response_module(response_dict['server_error']['code'], msg="Too many requests, please try again later")
                return False, msg, ''
            return False, response_dict['server_error'], ''
    except Exception as e:
        logger.error('register account failed. account: {}, error: {}'.format(account, repr(e)))
        return False, response_dict['server_error'], ''
    try:
        account_id = ""
        account_info = get_account(account['name'])
        if account_info:
            account_id = account_info["id"]
    except Exception as e:
        logger.error('get account failed. account: {}, error: {}'.format(account, repr(e)))
    return True, "", account_id
 
def account_count_check(ip, date):
    my_db = pymysql.connect(**db)
    cursor = my_db.cursor()

    try:
        query_sql = "select count(*) from {} where DATE_FORMAT(create_time, '%Y-%m-%d')='{}'".format(
            tables['users'], date)
        cursor.execute(query_sql)
        count = cursor.fetchone()[0]
        logger.debug('ip: {}, date: {}, count: {}. max_limit: {}'.format(ip, date, count, registrar_account_max))
        if has_account_max_limit and count > registrar_account_max:
            my_db.close()
            return False, response_dict['forbidden_today_max'], 0

        #ip max register check
        query_sql = "select count(*) from {} where ip='{}' and DATE_FORMAT(create_time, '%Y-%m-%d')='{}'".format(
            tables['users'], ip, date)
        cursor.execute(query_sql)
        this_ip_count = cursor.fetchone()[0]

        logger.debug('this_ip_count: {}, ip_max_limit: {}'.format(this_ip_count, ip_max_register_limit))
        if has_ip_max_limit and this_ip_count > ip_max_register_limit:
            my_db.close()
            return False, response_dict['forbidden_ip_max'], 0
    except Exception as e:
        my_db.close()
        logger.error('db failed. ip: {}, error: {}'.format(ip, repr(e)))
        return False, response_dict['server_error'], 0
    my_db.close()
    return True, '', count

def store_new_account(data):
    my_db = pymysql.connect(**db)
    cursor = my_db.cursor()

    try:
        create_time = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(sql['insertData'].format(data['id'], data['name'], data['active_key'], data['ip'], create_time, register))
        my_db.commit()
    except Exception as e:
        my_db.rollback()
        logger.error('execute insertData failed. data: {}, error: {}'.format(data, repr(e)))
    finally:
        my_db.close()


def get_account(name):
    try:
        body_relay = {
            "jsonrpc": "2.0",
            "method": "get_account",
            "params": [name],
            "id":1
        }
        response = json.loads(requests.post(cli_wallet_url, data = json.dumps(body_relay), headers = headers).text)
        if 'error' not in response:
            return response['result']
    except Exception as e:
        logger.error('get account failed. account: {}, error: {}'.format(account, repr(e)))
    return None

def time_str_to_stamp(str_time):
    return int(time.mktime(time.strptime(str_time, "%Y-%m-%d %H:%M:%S")))

def reward():
    while True:
        my_db = pymysql.connect(**db)
        cursor = my_db.cursor()
        try:
            today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
            query_sql = "select count(*) from {} where status={} and DATE_FORMAT(create_time, '%Y-%m-%d')='{}'".format(
                tables['users'], g_reward_status["SUCCESS"], today)
            cursor.execute(query_sql)
            count = cursor.fetchone()[0]

            str_time = (datetime.datetime.utcnow()-datetime.timedelta(seconds=6)).strftime("%Y-%m-%d %H:%M:%S")
            before_seconds_stamp = time_str_to_stamp(str_time)
            query_sql = "select id, name, status, create_time from {} where status < {} and register='{}' and DATE_FORMAT(create_time, '%Y-%m-%d')='{}'".format(
                tables['users'], g_reward_retry_count, register, today)
            cursor.execute(query_sql)
            results = cursor.fetchall()
            for result in results:
                account_name = result[1]
                status = result[2]
                create_time_stamp = time_str_to_stamp(result[3])
                account_info = get_account(account_name)
                if account_info and create_time_stamp < before_seconds_stamp:
                    account_id = account_info["id"]
                    reward_status = send_reward(count, account_id, account_name)
                    if account_id != result[0]:
                        logger.info('name: {}, status: {}, id: {} -> {}, reward_status: {}, create_time_stamp: {}, before seconds: {}'.format(
                        account_name, status, result[0], account_id, reward_status, create_time_stamp, before_seconds_stamp))
                    if reward_status != -1:
                        if reward_status == 0:
                            status = 4 #成功
                        else:
                            status = status + 1 #失败+1
                        update_sql = "update {} set status='{}', id='{}' where register='{}' and name='{}' ".format(
                            tables['users'], status, account_id, register, account_name)
                        cursor.execute(update_sql)
                        my_db.commit()
        except Exception as e:
            my_db.rollback()
            logger.error('reward exception. {}'.format(repr(e)))
        finally:
            my_db.close()
        time.sleep(5)

class FaucetHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-type, Accept, connection, User-Agent, Cookie, Authorization")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')

    def options(self):
        self.post()

    def post(self):
        auth = self.request.headers.get('authorization', '') 
        if auth not in auth_list.values():
            return self.write(response_dict['forbidden_no_auth'])  
        
        #ip black check
        remote_ip = self.request.remote_ip
        real_ip = self.request.headers.get('X-Real-IP')
        forwarded_ips  = self.request.headers.get('X-Forwarded-For')
        ip_data = 'remote_ip: {}, real_ip: {}, forwarded-for: {}'.format(remote_ip, real_ip, forwarded_ips)
        logger.info("request ip_data: {}, ip_limit_list: {}".format(ip_data, ip_limit_list))
        if real_ip is None:
            real_ip = remote_ip  
        if real_ip in ip_limit_list:
            return self.write(response_dict['forbidden_no_auth']) 
        
        # request params check
        data = json.loads(self.request.body.decode("utf8"))
        account = data.get("account")
        status, msg, account_data = params_valid(account)
        if not status:
            logger.error('status:{}, msg: {}, account_data: {}'.format(status, msg, account_data))
            return self.write(msg)

        # check register count
        today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
        status, msg, account_count = account_count_check(real_ip, today)
        logger.info('[account_count_check] real_ip: {}, today: {}, status: {}, msg: {}, account_count: {}'.format(
            real_ip, today, status, msg, account_count))
        if not status:
            return self.write(msg)
        
        status, msg, new_account_id = register_account(account_data)
        logger.info('status:{}, msg: {}, new_account_id: {}, account: {}'.format(status, msg, new_account_id, account_data))
        if not status:
            return self.write(msg)
        
        #store new account data
        account_data['id'] = new_account_id
        account_data['ip'] = real_ip
        store_new_account(account_data)

        #return
        del account_data['ip']
        return self.write(response_module(response_dict['ok']['code'], data={"account": account_data}, msg='Register successful! {}, {}'.format(account_data['name'], memo)))

def main():
    logger.info('-------------- faucet server start ----------------')
    initialize()

    reward_thread = Thread(target=reward)
    reward_thread.start()

    parse_command_line()
    app = tornado.web.Application(
        handlers=[
            (r'/api/v1/accounts', FaucetHandler),
        ],
    )
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.bind(options.port, address='0.0.0.0')
    http_server.start(2)
    tornado.ioloop.IOLoop.current().start()

if __name__ == '__main__':
    main()