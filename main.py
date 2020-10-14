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

    parser = optparse.OptionParser()
    parser.add_option("-q", dest="search_query", help="search single query (will disable -f)")
    parser.add_option("-f", dest="query_file_name", help="load queries from file")
    parser.add_option("-e", dest="export_type", help="save vulnerable url")
    parser.add_option("-r", dest="remove_terms", help="remove url containing the specified string")
    (options, args) = parser.parse_args()
    logger.info('[+] Parsed Options: %s' % str(options))

    queries = parse_query(options)
    logger.info('[+] %d queries detected | %s' % (len(queries), str(queries)))

    be = BingEngine()
    url_list = be.query_url(queries)

    # Remove URLs that contains specified string
    remove_url(options, url_list, logger)

    # Writes collated url to a file
    with open('url_list_2.txt', 'w') as f:
        for url in url_list:
            f.write("%s\n" % url)

    # Use an already collated url_list
    # with open('url_list.txt', 'r') as f:
    #     url_list = f.readlines()
    # f.close()

    logger.info('[+] Size of url_list: %d' % len(url_list))

    # s = Scanner(url_list)
    # result = s.execute()
    # #
    # if options.export_type:
    #     eg = ExportGenerator(result)
    #     eg.generate(options.export_type)
