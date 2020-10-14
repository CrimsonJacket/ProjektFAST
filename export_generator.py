#!/usr/bin/python
import csv
import datetime


class ExportGenerator:
    result = {}

    def __init__(self, result):
        self.results = result

    def csv(self, results):
        with open('output-{}.csv'.format(datetime.datetime.now().strftime('%d-%m-%Y %H-%M-%S')),
                  'a') as csvfile:  # append mode
            fieldnames = ['domain', 'values']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for i, j in results.items():
                writer.writerow({'domain': str(i), 'values': str(j)})

    def txt(self, results):
        with open('output-{}.txt'.format(datetime.datetime.now().strftime('%d-%m-%Y %H-%M-%S')),
                  'a') as txtfile:  # append mode
            for i, j in results.items():
                txtfile.write('Domain:{} Values:{} \n'.format(str(i), str(j)))

    def generate(self, type):
        if 'csv' in type:
            self.csv(self.results)
        elif 'txt' in type:
            self.txt(self.results)
        else:
            print("[!] Unable to generate output")
