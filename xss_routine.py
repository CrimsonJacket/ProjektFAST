#!/usr/bin/python3
import re
import urllib.request
from bs4 import BeautifulSoup
from core.log import setup_logger
from core.scan import scan
from core.dom import dom
from core.requester import requester


ENCODING = False
DELAY = 0
TIMEOUT = 10
SKIP_DOM = False
SKIP_OPT = True

HEADERS = {
    'User-Agent': '$', 
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5', 
    'Accept-Encoding': 'gzip,deflate', 
    'Connection': 'close', 
    'DNT': '1', 
    'Upgrade-Insecure-Requests': '1'
}

class XssRoutine:

    def __init__(self):
        self.LOGGER = setup_logger(__name__)

    def _retrieve_content(self, url):
        try:
            url = url.replace(' ', "%20")
            req = urllib.request.Request(url)
            retval = urllib.request.urlopen(req).read()
        except Exception as ex:
            self.LOGGER.error(f"Cannot retrieve content for url: {url}")
            retval = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
        return retval or ""

    def _contains(self, content, chars):
        content = re.sub(r"\\[%s]" % re.escape(
            "".join(chars)), "", content) if chars else content
        return all(char in content for char in chars)

    def scan_page(self, url, data=None):
        retval, usable = False, False
        url = re.sub(r"=(&|\Z)", "=1\g<1>", url)
        page_content = self._retrieve_content(url)

        soup = BeautifulSoup(str(page_content), 'html.parser')
        
        # TODO: Crawl for additional URLs in page.
        
        # links = soup.find_all(href=True)
        # self.LOGGER.info(f"{links}")
        
        # url_list = [url]
        
        # if len(links) > 0:
        #     for links in links:
        #         url_list.append(f"{url}")
        
        self.LOGGER.info(f"Scan Page: {url}")
        self.LOGGER.info('   - Checking for DOM vulnerabilities')
        response = requester(url, {}, HEADERS, True, DELAY, TIMEOUT).text
        highlighted = dom(response)
        
        if highlighted:
            self.LOGGER.good('   - Potentially vulnerable objects found')
            self.LOGGER.red_line(level='good')
            for line in highlighted:
                self.LOGGER.no_format(line, level='good')
            self.LOGGER.red_line(level='good')
            

        forms = soup.find_all('form')
        form_details = {}
        
        ret_value = {url : {}}

        for form in forms:
            inputs = []
            form_action = form.get('action')
            for form_input in form.find_all('input'):
                input_type = form_input.get('type', None)
                input_name = form_input.get('name', None)
                input_value = form_input.get('value', None)

                if input_type != 'text':
                    continue

                inputs.append({
                    'type': input_type,
                    'name': input_name,  # Important to determine name of the input
                })

            form_details.update({form_action: inputs})
                    
        for form, inputs in form_details.items():
            if len(inputs) < 1:
                continue
            # self.LOGGER.info(f"Inputs: {inputs}")

            # url_with_params = url + form + "?"
            param_discovery_list = []
            for item in inputs:
                param = item["name"]
                param_discovery_list.append(param)

            # self.LOGGER.info(f"URL(w/ params): {url_with_params}")
            # self.LOGGER.info(f"Input: {inputs}\n")
            url_form, vuln_params_payloads = scan(url, form, param_discovery_list, ENCODING, HEADERS, DELAY, TIMEOUT, SKIP_DOM, SKIP_OPT)
            ret_value[url].update({form: vuln_params_payloads})
        return ret_value