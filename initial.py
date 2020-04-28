# -*- coding:utf-8 -*-

import os
import socket

from sql import sql
from logger import logger
from alarm import push_message
from db import connection_pool
from pysdk import gph, get_asset, get_account, init_wallet
from config import register, db_config, limit_config as limit, reward_config, asset_config

def init_reward():
    try:
        properties = gph.rpc.get_object("2.0.0")
        transfer_fee = properties['parameters']['current_fees']['parameters'][0]
        if transfer_fee[0] == 0:
            core_asset = asset_config["core_asset"]
            asset = get_asset(core_asset["symbol"])
            asset_config["core_asset"]["precision"] = asset['precision']

            gas_asset = asset_config["gas_asset"]
            reward_gas = reward_config["gas_asset"]
            asset = get_asset(gas_asset["symbol"])
            logger.info("asset: {}, reward: {}".format(asset_config, reward_config))
            asset_config["gas_asset"]["precision"] = asset['precision']
            core_exchange_rate = asset['options']['core_exchange_rate']
            logger.info("core_exchange_rate: {}".format(core_exchange_rate))

            qute_amount = core_exchange_rate['quote']['amount']
            base_amount = core_exchange_rate['base']['amount']
            exchange_rate = round(qute_amount/base_amount)
            asset_config["gas_asset"]["exchange_rate"] = exchange_rate
            reward_config["gas_asset"]["amount"] = transfer_fee[1]['fee']*exchange_rate*reward_gas["NTransfer"]

            logger.info("init register({}) account id".format(register["name"]))
            register_account = get_account(register["name"])
            if register_account:
                register["id"] = register_account["id"]
            else:
                logger.error("get_account {} failed".format(register["name"]))
            logger.info('register:{}, id:{}, reward config:{}, transfer fee:{}, asset config: {}'.format(register["name"],
                register["id"], reward_config, transfer_fee, asset_config))
    except Exception as e:
        logger.error('init failed. error: {}'.format(repr(e)))
        push_message("init reward error")

def init_database():
    with connection_pool(db_config).cursor() as cursor:
        try:
            cursor.execute(sql["createTable"])
        except Exception as e:
            logger.warn('init failed. error: {}'.format(repr(e)))

def init_host_info():
    global g_hostname, g_ip
    try:
        g_hostname = socket.getfqdn(socket.gethostname())
        g_ip = socket.gethostbyname(g_hostname)
    except Exception as e:
        logger.warn('init host info. error: {}'.format(repr(e)))
    if 'HOST_NAME' in os.environ:
        g_hostname = os.environ['HOST_NAME']
    logger.info('hostname: {}, ip: {}'.format(g_hostname, g_ip))

def initialize():
    logger.info("init wallet")
    init_wallet()
    logger.info("init host info")
    init_host_info()
    logger.info("init database")
    init_database()
    logger.info("init reward")
    init_reward()
    logger.info('ip blacklist: {}'.format(limit["blacklist"]))
    logger.info('init done.')
