# -*- coding:utf-8 -*-

import os
import json
import random
import pymysql
import requests
import datetime
import time
import socket

from config import *
from utils import *
from threading import Thread

import tornado.ioloop, tornado.web, tornado.httpserver
from tornado.options import define, options, parse_command_line

from logger import logger
from pysdk import gph, get_account, get_account_balance, create_account, transfer, update_collateral_for_gas
from initial import initialize
from alarm import push_message
from db import connection_pool

define('port', default=8041, type=int)

def params_valid(account):
    logger.info('account: {}'.format(account))
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

def send_reward_transfer(account_name, memo=memo):
    try:
        balance = get_account_balance(register, asset_core)
        if balance is None:
            return False
        core_amount = balance["amount"]
        logger.debug("{} balance: {} {}".format(register, core_amount, asset_core))
        if reward_core < core_amount:
            status = transfer(register, account_name, reward_core, asset_core, memo)
            if status:
                return True
            else:
                message = 'transfer to {} failed.'.format(account_name)
                logger.warn(message)
        else:
            message = 'register {} no enough {}({}), reward need {}'.format(
                register, asset_core, core_amount/(10**asset_core_precision), reward_core)
            logger.warn(message)
    except Exception as e:
        message = 'register {} no {}, reward need {}'.format(register, asset_core, reward_core)
        logger.error('{}, error: {}'.format(message, repr(e)))
    return False

def send_reward_gas(account_id):
    try:
        balance = get_account_balance(register, asset_gas)
        if balance is None:
            return False
        gas_amount = balance["amount"]
        logger.debug("{} balance: {} {}".format(register, gas_amount, asset_gas))
        if reward_gas/(10**asset_gas_precision) < gas_amount:
            status = update_collateral_for_gas(register_id, account_id, reward_gas)
            if status:
                return True
            else:
                message = 'update_collateral_for_gas to {} failed.'.format(account_id)
                logger.warn(message)
        else:
            message = 'register {} no enough {}({}), collateral need {}'.format(
                register, asset_gas, gas_amount, reward_gas/(10**asset_gas_precision))
            logger.warn(message)
    except Exception as e:
        message = 'register {} no {}, reward need {}'.format(register, asset_gas, reward_gas/(10**asset_gas_precision))
        logger.error('{}, error: {}'.format(message, repr(e)))
    return False

def send_reward(core_asset_transfer_count, account_id, account_name):
    if core_asset_transfer_count < reward_core_until_N:
        transfer_status = send_reward_transfer(account_name)
    else:
        transfer_status = False
    collateral_status = send_reward_gas(account_id)
    if transfer_status or collateral_status:
        return 0  # success
    else:
        return 1  # failed

def register_account(account):
    try:
        status = create_account(account['name'], account['owner_key'], account['active_key'],
                                account['active_key'], register)
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

def account_count_check(ip, date):
    with connection_pool(db_config).cursor() as cursor:
        try:
            # Daily Max
            query_sql = "SELECT COUNT(id) AS count FROM {} WHERE DATE_FORMAT(create_time, '%Y-%m-%d')='{}'".format(
                tables['users'], date)
            cursor.execute(query_sql)
            daily_result = cursor.fetchone()
            logger.debug('ip: {}, date: {}, fetch result: {}. max_limit: {}'.format(ip, date, daily_result, registrar_account_max))
            if has_account_max_limit and daily_result["count"] > registrar_account_max:
                return False, response_dict['forbidden_today_max'], 0

            #ip max register check
            query_sql = "SELECT count(id) AS count FROM {} WHERE ip='{}' AND DATE_FORMAT(create_time, '%Y-%m-%d')='{}'".format(
                tables['users'], ip, date)
            cursor.execute(query_sql)
            single_account_result = cursor.fetchone()
            logger.debug('fetch result: {}, ip_max_limit: {}'.format(single_account_result, ip_max_register_limit))
            if has_ip_max_limit and single_account_result["count"] > ip_max_register_limit:
                return False, response_dict['forbidden_ip_max'], 0
        except Exception as e:
            logger.error('db failed. ip: {}, error: {}'.format(ip, repr(e)))
            return False, response_dict['server_error'], 0
        return True, '', daily_result["count"]

def store_new_account(data):
    with connection_pool(db_config).cursor() as cursor:
        try:
            create_time = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(sql['create_account'].format(data['id'], data['name'], data['active_key'], data['ip'], create_time, register))
            # cursor.commit()
        except Exception as e:
            logger.error('execute create_account sql failed. data: {}, error: {}'.format(data, repr(e)))

def time_str_to_stamp(str_time):
    return int(time.mktime(time.strptime(str_time, "%Y-%m-%d %H:%M:%S")))

def reward():
    while True:
        with connection_pool(db_config).cursor() as cursor:
            try:
                today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
                query_sql = "SELECT COUNT(id) AS count FROM {} WHERE status={} AND DATE_FORMAT(create_time, '%Y-%m-%d')='{}'".format(
                    tables['users'], g_reward_status["SUCCESS"], today)
                # logger.debug(query_sql)
                cursor.execute(query_sql)
                core_asset_transfer_count = cursor.fetchone()["count"]
                # core_asset_transfer_count = result["count"]

                str_time = (datetime.datetime.utcnow()-datetime.timedelta(seconds=6)).strftime("%Y-%m-%d %H:%M:%S")
                before_seconds_stamp = time_str_to_stamp(str_time)
                query_sql = "SELECT account_id, name, status, create_time FROM {} WHERE status < {} AND register='{}' AND DATE_FORMAT(create_time, '%Y-%m-%d')='{}'".format(
                    tables['users'], g_reward_retry_count, register, today)
                # logger.debug(query_sql)
                cursor.execute(query_sql)
                results = cursor.fetchall()
                # logger.debug(results)
                for result in results:
                    account_name = result["name"]
                    status = result["status"]
                    create_time_stamp = time_str_to_stamp(result["create_time"])
                    account_info = get_account(account_name)
                    if account_info and create_time_stamp < before_seconds_stamp:
                        account_id = account_info["id"]
                        reward_status = send_reward(core_asset_transfer_count, account_id, account_name)
                        if account_id != result["account_id"]:
                            logger.info('name: {}, status: {}, id: {} -> {}, reward_status: {}, create_time_stamp: {}, before seconds: {}'.format(
                            account_name, status, result["account_id"], account_id, reward_status, create_time_stamp, before_seconds_stamp))
                        if reward_status != -1:
                            if reward_status == 0:
                                status = 4 #success
                            else:
                                status = status + 1 #failed +1
                            update_sql = "UPDATE {} SET STATUS='{}', account_id='{}' WHERE register='{}' AND name='{}' ".format(
                                tables['users'], status, account_id, register, account_name)
                            cursor.execute(update_sql)
                            # cursor.commit()
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
