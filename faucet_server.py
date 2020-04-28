# -*- coding:utf-8 -*-

import os
import json
import random
import requests
import datetime
import time

from threading import Thread
import tornado.ioloop, tornado.web, tornado.httpserver
from tornado.options import define, options, parse_command_line

from utils import *
from sql import sql
from logger import logger
from initial import initialize
from alarm import push_message
from db import connection_pool
from config import (register, default_memo, asset_config, limit_config, db_config, auth_list, reward_config)
from pysdk import gph, get_account, get_account_balance, create_account, transfer, update_collateral_for_gas

define('port', default=8041, type=int)

def request_params_check(account):
    logger.debug("account: {}".format(account))
    name = account.get('name', '')
    active_key = account.get('active_key', '')
    owner_key = account.get('owner_key', '')
    if not name:
        return False, response_dict['bad_request'], {}
    if not is_cheap_name(name):
        return False, response_dict['not_cheap_account'], {}
    account_object = get_account(name)
    if account_object:
        return False, response_dict['account_registered'], {}

    if not active_key:
        return False, response_dict['bad_request'], {}
    if not owner_key:
        owner_key = active_key

    if not is_valid_name(name):
        msg = response_module(response_dict['bad_request']['code'], msg="account {} illegal".format(name))
        return False, msg, {}
    return True, '', {'name': name, 'active_key': active_key, 'owner_key': owner_key}

def send_reward_core_asset(account_name, memo=default_memo):
    core_symbol = asset_config["core_asset"]["symbol"]
    reward_core = reward_config["core_asset"]["amount"]
    try:
        balance = get_account_balance(register["name"], core_symbol)
        if balance is None:
            return False
        core_amount = balance["amount"]
        logger.debug("{} balance: {} {}".format(register["name"], core_amount, core_symbol))
        if reward_core < core_amount:
            status = transfer(register["name"], account_name, reward_core, core_symbol, memo)
            if status:
                return True
            else:
                message = 'transfer to {} failed.'.format(account_name)
                logger.warn(message)
        else:
            logger.warn('register {} no enough {}({}), reward need {}'.format(register["name"],
                core_symbol, core_amount, reward_core))
    except Exception as e:
        message = 'register {} no {}, reward need {}'.format(register["name"], core_symbol, reward_core)
        logger.error('{}, error: {}'.format(message, repr(e)))
    return False

def send_reward_gas_asset(account_id):
    gas_asset = asset_config["gas_asset"]
    precision = 10**gas_asset["precision"]
    reward_gas = reward_config["gas_asset"]["amount"]
    try:
        balance = get_account_balance(register["name"], gas_asset["symbol"])
        if balance is None:
            return False
        gas_amount = balance["amount"]
        logger.debug("{} balance: {} {}".format(register["name"], gas_amount, gas_asset["symbol"]))
        if reward_gas/precision < gas_amount:
            status = update_collateral_for_gas(register["id"], account_id, reward_gas)
            if status:
                return True
            else:
                message = 'update_collateral_for_gas to {} failed.'.format(account_id)
                logger.warn(message)
        else:
            message = 'register {} no enough {}({}), collateral need {}'.format(
                register["name"], gas_asset["symbol"], gas_amount, reward_gas/precision)
            logger.warn(message)
    except Exception as e:
        message = 'register {} no {}, reward need {}'.format(register["name"], gas_asset["symbol"],
            reward_gas/precision)
        logger.error('{}, error: {}'.format(message, repr(e)))
    return False

def send_reward(core_asset_transfer_count, account_id, account_name):
    if core_asset_transfer_count < limit_config["daily_max"]["amount"]:
        transfer_status = send_reward_core_asset(account_name)
    else:
        transfer_status = False
    collateral_status = send_reward_gas_asset(account_id)
    return (transfer_status or collateral_status)

def register_account(account):
    try:
        status = create_account(account['name'], account['owner_key'], account['active_key'],
                                account['active_key'], register["name"])
        if not status:
            return False, "register account failed", ''
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

def register_check(ip):
    try:
        with connection_pool(db_config).cursor() as cursor:
            daily_max = limit_config["daily_max"]
            today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
            if daily_max["enable"]:
                cursor.execute(sql["dailyCountQuery"].format(today))
                daily_result = cursor.fetchone()
                logger.debug('ip:{}, date:{}, fetch result:{}. max_limit:{}'.format(ip, today, daily_result, daily_max))
                if daily_result["count"] > daily_max["amount"]:
                    return False, response_dict['forbidden_today_max']

            address_max = limit_config["address_max"]
            if address_max["enable"]:
                cursor.execute(sql["addressCountQuery"].format(ip, today))
                address_result = cursor.fetchone()
                logger.debug('fetch result: {}, address_max: {}'.format(address_result, address_max))
                if address_result["count"] > address_max["amount"]:
                    return False, response_dict['forbidden_ip_max']
            return True, ''
    except Exception as e:
        logger.error('db failed. ip_address: {}, error: {}'.format(ip, repr(e)))
        return False, response_dict['server_error']

def save_new_account(data):
    try:
        with connection_pool(db_config).cursor() as cursor:
            create_time = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(sql['createAccount'].format(data['id'], data['name'], data['active_key'],
                data['address'], create_time, register["name"]))
    except Exception as e:
        logger.error('execute create_account sql failed. data: {}, error: {}'.format(data, repr(e)))

def time_str_to_stamp(str_time):
    return int(time.mktime(time.strptime(str_time, "%Y-%m-%d %H:%M:%S")))

def reward():
    while True:
        try:
            with connection_pool(db_config).cursor() as cursor:
                today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
                cursor.execute(sql["dailySuccessQuery"].format(g_reward_status["SUCCESS"], today))
                fetch_result = cursor.fetchone()
                daily_success_count = fetch_result["count"]

                str_time = (datetime.datetime.utcnow()-datetime.timedelta(seconds=6)).strftime("%Y-%m-%d %H:%M:%S")
                before_seconds_stamp = time_str_to_stamp(str_time)
                cursor.execute(sql["rewardQuery"].format(reward_failed_retry_times, register["name"], today))
                accounts = cursor.fetchall()
                for account in accounts:
                    status = account["status"]
                    old_account_id = account["account_id"]
                    create_time_stamp = time_str_to_stamp(account["create_time"])
                    account_info = get_account(account["name"])
                    if account_info and create_time_stamp < before_seconds_stamp:
                        reward_status = send_reward(daily_success_count, account_info["id"], account["name"])
                        if reward_status:
                            status = 4 #success
                        else:
                            status = status + 1 #failed +1
                        cursor.execute(sql["statusUpdate"].format(status, account_info["id"], register["name"], account["name"]))

                        if account_info["id"] != old_account_id:
                            logger.info('name: {}, status: {}, id: {} -> {}, reward_status: {}, create_time_stamp: {}, before seconds: {}'.format(
                            account["name"], status, old_account_id, account_info["id"], reward_status, create_time_stamp, before_seconds_stamp))
        except Exception as e:
            logger.error('reward exception. {}'.format(repr(e)))
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
        request_address = {
            "remote": self.request.remote_ip,
            "real": self.request.headers.get('X-Real-IP'),
            "forwarded": self.request.headers.get('X-Forwarded-For')
        }
        logger.info("request address: {}".format(request_address))
        real_address = request_address["real"]
        if not real_address:
            real_address = request_address["remote"]
        if limit_config["blacklist"]["enable"] and real_address in limit_config["blacklist"]["ips"]:
            return self.write(response_dict['forbidden_no_auth'])

        # request params check
        # request data format: {"account":{"name":"new-account-name","owner_key":"","active_key":""}}
        request_data = json.loads(self.request.body.decode("utf8"))
        request_account = request_data.get("account")
        status, msg, account_data = request_params_check(request_account)
        if not status:
            logger.warn('status:{}, msg: {}, account_data: {}'.format(status, msg, account_data))
            return self.write(msg)

        # check register count
        status, msg = register_check(real_address)
        logger.info('[register_check] status: {}, msg: {}'.format(status, msg))
        if not status:
            return self.write(msg)

        status, msg, new_account_id = register_account(account_data)
        logger.info('status:{}, msg: {}, new_account_id: {}, account: {}'.format(status, msg, new_account_id, account_data))
        if not status:
            return self.write(msg)

        #save db
        account_data['id'] = new_account_id
        account_data['address'] = real_address
        save_new_account(account_data)

        #return
        del account_data['address']
        message = response_module(response_dict['ok']['code'], data={"account": account_data}, msg='Register successful! {},\
             {}'.format(account_data['name'], default_memo))
        return self.write(message)

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
