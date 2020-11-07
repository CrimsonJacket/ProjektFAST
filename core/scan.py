import copy
import re
from urllib.parse import urlparse, quote, unquote

from core.checker import checker
from core.colors import good, bad, end, info, green, red, que
import core.config
from core.config import xsschecker, minEfficiency
from core.dom import dom
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.utils import getUrl, getParams, getVar
from core.log import setup_logger



logger = setup_logger(__name__)


def scan(target, paramData, encoding, headers, delay, timeout, skipDOM, skip):
    GET, POST = (True, False)
    # If the user hasn't supplied the root url with http(s), we will handle it
    if not target.startswith('http'):
        try:
            response = requester('https://' + target, {},
                                 headers, GET, delay, timeout)
            target = 'https://' + target
        except:
            target = 'http://' + target
    logger.info('Scan target: {}'.format(target))
    response = requester("http://127.0.0.1:3000", {}, headers, GET, delay, timeout).text
    
    logger.info(f"{response}")

    
    if not skipDOM:
        logger.info('   - Checking for DOM vulnerabilities')
        highlighted = dom(response)
        logger.info(f"Highlighted: {highlighted}")
        if highlighted:
            logger.good('   - Potentially vulnerable objects found')
            logger.red_line(level='good')
            for line in highlighted:
                logger.no_format(line, level='good')
            logger.red_line(level='good')
            
    url = target
    
    params = {p: "" for p in paramData}
    
    vuln_params = {}
    
    for paramName in params.keys():
        paramsCopy = copy.deepcopy(params)

        paramsCopy[paramName] = xsschecker
        response = requester(url+"/", paramsCopy, headers, GET, delay, timeout)
        
        logger.debug(f"Response: {response.text}")
        
        occurences = htmlParser(response, encoding)
        positions = occurences.keys()
        logger.debug('Scan occurences: {}'.format(occurences))
        if not occurences:
            logger.error('No reflection found')
            continue
        else:
            logger.info('   - Reflections found: %i' % len(occurences))

        efficiencies = filterChecker(
            url, paramsCopy, headers, GET, delay, occurences, timeout, encoding)
        logger.debug('Scan efficiencies: {}'.format(efficiencies))
        vectors = generator(occurences, response.text)
        total = 0
        for v in vectors.values():
            total += len(v)
        if total == 0:
            logger.error('No vectors were crafted.')
            continue
        # logger.info('Payloads generated: %i' % total)
        progress = 0
        
        payloads_used = []

        for confidence, vects in vectors.items():
            for vect in vects:
                loggerVector = vect
                progress += 1
                logger.run(f'Analysing Reflections - Progress: {progress}/{total}\r')
                if not GET:
                    vect = unquote(vect)
                efficiencies = checker(
                    url, paramsCopy, headers, GET, delay, vect, positions, timeout, encoding)
                if not efficiencies:
                    for i in range(len(occurences)):
                        efficiencies.append(0)
                bestEfficiency = max(efficiencies)
                if bestEfficiency == 100 or (vect[0] == '\\' and bestEfficiency >= 95):
                    payloads_used.append(loggerVector)
                    
        logger.red_line(level='good')
        vuln_params.update({paramName: payloads_used})

    # logger.info(f"{url, vuln_params}")
    return url, vuln_params