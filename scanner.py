#!/usr/bin/python
import time
import logging
from xss_routine import XssRoutine
from shodan_routine import ShodanRoutine
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed


class Scanner:

    def __init__(self, url_list):
        self.URL_LIST = url_list
        self.RESULT = {}
        self.LOGGER = logging.getLogger(__name__)
        self.LOGGER.setLevel(logging.INFO)

        # create a file handler
        handler = logging.FileHandler('FAST.log')
        handler.setLevel(logging.INFO)

        # create a logging format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        # add the handlers to the self.LOGGER
        self.LOGGER.addHandler(handler)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        self.LOGGER.addHandler(stream_handler)

    def main_scan_routine(self, url):
        # domain = urlparse(url).hostname
        # sd_r = ShodanRoutine()

        # self.RESULT.update({domain: {}})

        # time.sleep(0.5)
        # self.LOGGER.info("[-] Starting Shodan Routine on domain: %s" % str(domain))
        # self.RESULT[domain].update({"shodan_result": sd_r.query_domain(domain)})
        # self.LOGGER.info("[+] Shodan Routine successfully processed domain: %s" % str(domain))

        # time.sleep(0.5)
        self.LOGGER.info("[-] Starting XSS Scanner on url: %s" % str(url))
        xss_r = XssRoutine()
        scan_result = xss_r.scan_page(url)

        if scan_result[0]:
            self.LOGGER.info("[+] Potential vulnerable URL: " +
                             url + " @" + scan_result[1])
            self.RESULT.update({"xss_result":
                                {"vul_url": url,
                                 "vul_parameter": scan_result[1]
                                 }
                                }
                               )
        self.LOGGER.info(
            "[+] XSS Scanner successfully processed url: %s" % str(url))

    def execute(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(
                Scanner.main_scan_routine, self, url): url for url in self.URL_LIST}

        as_completed(future_to_url)

        self.LOGGER.info('Completed')
        return self.RESULT
