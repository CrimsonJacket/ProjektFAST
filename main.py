import logging
import optparse
from bing_engine import BingEngine
from scanner import Scanner
from export_generator import ExportGenerator


def parse_query(options):
    parsed_queries = []
    if options.query_file_name and not options.search_query:
        parsed_queries = get_queries(options.query_file_name)
    else:
        parsed_queries.append(options.search_query)

    return parsed_queries


def get_queries(file_path):
    try:
        with open(file_path) as f:
            content = f.readlines()
        f.close()
        return [x.strip() for x in content]
    except:
        print.info("[!] Unable to read queries from file")


def remove_url(options, url_to_scan, logger):
    if options.remove_terms:
        split_terms = [x.strip() for x in options.remove_terms.split(',')]
        logger.info("[+] Number of url before removing terms: " + str(len(url_to_scan)))
        logger.info("[+] Removing terms containing: " + str(split_terms))

        for i in split_terms:
            for url in url_to_scan:
                if i in url:
                    url_to_scan.remove(url)
        logger.info("[+] Number of url after removing terms: " + str(len(url_to_scan)))


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    # create a file handler
    handler = logging.FileHandler('FAST.log')
    handler.setLevel(logging.INFO)

    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(handler)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.info('=== Starting FAST ===')

    s = Scanner("127.0.0.1")
    result = s.execute()
    
    if options.export_type:
        eg = ExportGenerator(result)
        eg.generate(options.export_type)
