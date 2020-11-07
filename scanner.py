#!/usr/bin/python
import time
import logging
from xss_routine import XssRoutine
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.log import setup_logger

class Scanner:

    def __init__(self, url_list):
        self.URL_LIST = url_list
        self.RESULT = {}
        self.LOGGER = setup_logger(__name__)


    def main_scan_routine(self, url):
        self.LOGGER.info("[-] Starting XSS Scanner on url: %s" % str(url))
        self.LOGGER.red_line(level='good')

        xss_r = XssRoutine()
        scan_result = xss_r.scan_page(url)
                
        for base_url, forms in scan_result.items():
            for form, param_details in forms.items():
                if len(list(param_details.values())) < 1:
                    continue
                self.LOGGER.info(f"[+] Vulnerability found on URL: {base_url}{form}")
                for param, payload_list in param_details.items():
                    self.LOGGER.info(f"   - Vulnerable parameter: {param}")
                    self.LOGGER.info(f"      - Example Payload used: {payload_list[0]}")

        self.LOGGER.info(f"[+] XSS Scanner successfully processed {len(scan_result.values().keys())} URLs")

    def execute(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(Scanner.main_scan_routine, self, url): url for url in self.URL_LIST}

        as_completed(future_to_url)

        return self.RESULT
