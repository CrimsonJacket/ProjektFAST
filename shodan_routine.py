#!/usr/bin/python
import requests
import socket
import logging


class ShodanRoutine:
    API_KEY_FILE_PATH = "./shodanapi.txt"
    SHODAN_API_KEY = "lmUQqr2cUXWDF1znkLZOTXOMWKMxuzTE"
    MINIFY = 'false'

    def __init__(self):
        self.LOGGER = logging.getLogger(__name__)
        self.LOGGER.setLevel(logging.INFO)

        # create a file handler
        handler = logging.FileHandler('FAST.log')
        handler.setLevel(logging.INFO)

        # create a logging format
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        # add the handlers to the self.LOGGER
        self.LOGGER.addHandler(handler)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        self.LOGGER.addHandler(stream_handler)

    def get_shodan_api_key(self):
        try:
            with open(self.API_KEY_FILE_PATH) as f:
                content = f.readline().strip()
            f.close()
            return content
        except:
            self.LOGGER.info("[!] Unable to get shodan api")

    def query_domain(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            self.LOGGER.info(ip)
            response = requests.get(
                "https://api.shodan.io/shodan/host/{}?key={}&minify={}".format(ip, self.SHODAN_API_KEY, self.MINIFY))

            return response.content
        except:
            self.LOGGER.info("[-] Unable get request from shodan.io")
