# -*- coding:utf-8 -*-

import json
import requests
from logger import logger
from config import alert_address, env_config as config

def push_message(message, labels=['faucet']):
    content = "[{}]{} {}, {}".format(config["env"], str(labels), config["hostname"], message)
    logger.debug('push content: {}'.format(content))
    return    # no need

    try:
        body_relay = {
            "jsonrpc": "2.0",
            "msgtype": "text",
            "text": { "content": content },
            "id":1
        }
        json.loads(requests.post(alert_address,
            data = json.dumps(body_relay), headers={"content-type": "application/json"}).text)
    except Exception as e:
        logger.error('push error. {}'.format(repr(e)))