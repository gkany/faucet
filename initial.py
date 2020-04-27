# -*- coding:utf-8 -*-

import os
import pymysql

from logger import logger
from pysdk import gph
from alarm import push_message
from config import *
from db import connection_pool

def init_wallet():
    try:
        if not gph.wallet.created():
            gph.newWallet(wallet_password)
        logger.info("wallet create status: {}".format(gph.wallet.created()))

        if gph.wallet.locked():
            gph.wallet.unlock(wallet_password)
        logger.info("wallet lock status: {}".format(gph.wallet.locked()))

        if gph.wallet.getPrivateKeyForPublicKey(register_public_key) is None:
            logger.info("import private key into wallet. public key: {}".format(register_public_key))
            gph.wallet.addPrivateKey(register_private_key)

        logger.info("account id: {}, public key: {}".format(
            gph.wallet.getAccountFromPublicKey(register_public_key), register_public_key))

        config["default_prefix"] = gph.rpc.chain_params["prefix"]
        config["default_account"] = register
    except Exception as e:
        print(repr(e))

def init_reward():
    global asset_core_precision, core_exchange_rate, reward_gas
    global gas_core_exchange_rate, register_id, asset_gas_precision

    try:
        properties = gph.rpc.get_object("2.0.0")
        transfer_fee = properties['parameters']['current_fees']['parameters'][0]
        if transfer_fee[0] == 0:
            logger.info("asset {}".format(asset_core))
            asset = get_asset(asset_core)
            asset_core_precision = asset['precision']
            logger.info("asset {} precision: {}".format(asset_core, asset_core_precision))

            logger.info("asset {}".format(asset_gas))
            asset = get_asset(asset_gas)
            asset_gas_precision = asset['precision']
            core_exchange_rate = asset['options']['core_exchange_rate']
            gas_core_exchange_rate = round(core_exchange_rate['quote']['amount']/core_exchange_rate['base']['amount'])
            logger.info("asset {} precision: {}, gas_exchange_rate: {}".format(asset_gas,
                asset_gas_precision, gas_core_exchange_rate))
            reward_gas = transfer_fee[1]['fee'] * gas_core_exchange_rate * transfer_operation_N

            logger.info("init register({}) account id".format(register))
            register_account = get_account(register)
            if register_account:
                register_id = register_account["id"]
            else:
                logger.error("get_account {} failed".format(register))
            logger.info('register:{}, id:{}, gas rate:{}, reward_gas:{}, reward_core:{}, transfer fee:{}'.format(
                register, register_id, gas_core_exchange_rate, reward_gas, reward_core, transfer_fee))
    except Exception as e:
        logger.error('init failed. error: {}'.format(repr(e)))
        push_message("init reward error")

def init_database():
    with connection_pool(db_config).cursor() as cursor:
        try:
            cursor.execute(sql["create_table"])
            # cursor.commit()
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
    logger.info('ip_limit_list: {}'.format(ip_limit_list))
    logger.info('init done.')
