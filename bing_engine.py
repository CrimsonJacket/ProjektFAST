#!/usr/bin/python
import time
import logging
import requests


class BingEngine:
    API_KEY_FILE_PATH = "./bingapi.txt"
    BING_API_KEY = ""
    BING_SEARCH_API_END_POINT = "https://api.cognitive.microsoft.com/bing/v7.0/search"
    QUERIES = []
    EXTENSION = ["php", "jsp"]

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

        self.BING_API_KEY = self.get_bing_api_key()
        self.LOGGER.info("[+] Retrieved Bing Engine API Key")

    def get_bing_api_key(self):
        try:
            with open(self.API_KEY_FILE_PATH) as f:
                content = f.readline().strip()
            f.close()
            return content
        except:
            print("[!] Unable to get bing api")

    def retrieve_url(self, extension, query_parameter):
        url_list = []
        try:
            search_term = "instreamset:(url):'." + extension + "?" + query_parameter + "='"
            headers = {"Ocp-Apim-Subscription-Key": self.BING_API_KEY}
            params = {"q": search_term, "textDecorations": True, "count": 50}
            response = requests.get(BingEngine.BING_SEARCH_API_END_POINT, headers=headers, params=params)
            # response.raise_for_status()
            search_results = response.json()
            for i in search_results["webPages"]["value"]:
                url_list.append(i["url"])
        except Exception as e:
            print("Error: " + str(e))

        return url_list

    def query_url(self, queries):
        url_list = []
        self.LOGGER.info(self.EXTENSION)
        for ext in self.EXTENSION:
            for query in queries:
                self.LOGGER.info("[+] Retrieving extension: " + ext + " | query: " + query)
                url_list.extend(self.retrieve_url(ext, query))
                self.LOGGER.info("[+] Number of URLs: " + str(len(url_list)))
                time.sleep(1)
        return url_list
