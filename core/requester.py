import random
import requests
import time
from urllib3.exceptions import ProtocolError
import warnings

import core.config
from core.utils import converter, getVar
from core.log import setup_logger

logger = setup_logger(__name__)

warnings.filterwarnings('ignore')  # Disable SSL related warnings


def requester(url, data, headers, GET, delay, timeout):
    try:
        if GET:
            response = requests.get(url, params=data, headers=headers,
                                    timeout=timeout, verify=False)
        else:
            response = requests.post(url, data=data, headers=headers,
                                     timeout=timeout, verify=False)
        return response
    except ProtocolError:
        logger.info("Error here")
        logger.warning('WAF is dropping suspicious requests.')
        logger.warning('Scanning will continue after 10 minutes.')
        time.sleep(600)
