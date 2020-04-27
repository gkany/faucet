# -*- coding:utf-8 -*-

import json
import requests
from logger import logger
from config import faucet_alert_address, headers, g_hostname, env

def push_message(message, labels=['faucet']):
    content = "[{}]{} {}, {}".format(env, str(labels), g_hostname, message)
    logger.debug('push content: {}'.format(content))
    return    # no need

    try:
        body_relay = {
            "jsonrpc": "2.0",
            "msgtype": "text",
            "text": { "content": content },
            "id":1
        }
        json.loads(requests.post(faucet_alert_address,
            data = json.dumps(body_relay), headers = headers).text)
    except Exception as e:
        logger.error('push error. {}'.format(repr(e)))