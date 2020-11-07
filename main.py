import argparse

from scanner import Scanner



if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help='url', dest='target')
    
    args = parser.parse_args()
    
    target = args.target

    s = Scanner([target])
    result = s.execute()

