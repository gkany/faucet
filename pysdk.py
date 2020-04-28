# -*- coding:utf-8 -*-

from PythonMiddleware.graphene import Graphene
from PythonMiddleware.instance import set_shared_graphene_instance
from PythonMiddleware.account import Account
from PythonMiddleware.asset import Asset
from PythonMiddleware.storage import configStorage

from logger import logger
from config import register, sdk_config

gph = Graphene(node=sdk_config["node_address"], blocking=True)
set_shared_graphene_instance(gph)

def get_account(name):
    try:
        account = Account(name)
        return account
    except Exception as e:
        error_msg = repr(e)
        logger.warn('name {}, error: {}'.format(name, repr(e)))
        return None

def create_account(name, owner_key, active_key, memo_key, registrar):
    try:
        response = gph.create_account(account_name=name, registrar=registrar,
                           owner_key=owner_key, active_key=active_key, memo_key=memo_key)
        logger.debug(response)
    except Exception as e:
        logger.error('name {}, error: {}'.format(name, repr(e)))
        return False
    return True

def transfer(from_account, to, amount, asset="1.3.0", memo=""):
    try:
        response = gph.transfer(to=to, amount=amount, asset=asset, memo=[memo,0], account=from_account)
        logger.debug(response)
    except Exception as e:
        logger.error('to {}, amount: {}, error: {}'.format(to, amount, repr(e)))
        return False
    return True

def update_collateral_for_gas(from_account, beneficiary, collateral):
    try:
        response = gph.update_collateral_for_gas(beneficiary=beneficiary, collateral=collateral,
                account=from_account)
        logger.debug(response)
    except Exception as e:
        logger.error('from:{}, beneficiary {}, collateral: {}, error: {}'.format(
            from_account, beneficiary, collateral, repr(e)))
        return False
    return True

def get_account_balance(name, symbol):
    try:
        account = get_account(name)
        if account is None:
            return None
        else:
            balance = account.balance(symbol)
            return balance
    except Exception as e:
        logger.error('name {}, symbol {}, error: {}'.format(name, symbol, repr(e)))
        return None

def get_asset(symbol):
    try:
        asset = Asset(symbol)
        return asset
    except Exception as e:
        logger.error('symbol {}, error: {}'.format(symbol, repr(e)))
        return None

def init_wallet():
    try:
        if not gph.wallet.created():
            gph.newWallet(sdk_config["wallet_password"])
        logger.info("wallet create status: {}".format(gph.wallet.created()))

        if gph.wallet.locked():
            gph.wallet.unlock(sdk_config["wallet_password"])
        logger.info("wallet lock status: {}".format(gph.wallet.locked()))

        if gph.wallet.getPrivateKeyForPublicKey(register["public_key"]) is None:
            logger.info("import private key into wallet. public key: {}".format(
                register["public_key"]))
            gph.wallet.addPrivateKey(register["private_key"])

        logger.info("account id: {}, public key: {}".format(
            gph.wallet.getAccountFromPublicKey(register["public_key"]),
            register["public_key"]))

        configStorage["default_prefix"] = gph.rpc.chain_params["prefix"]
        configStorage["default_account"] = register["name"]
    except Exception as e:
        logger.error("init sdk wallet exception. {}".format(repr(e)))
