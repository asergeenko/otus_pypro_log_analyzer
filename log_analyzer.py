# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import os
import logging
import gzip
import re
import json
from datetime import date,datetime

from string import Template
from collections import OrderedDict

import argparse

parser = argparse.ArgumentParser(description="Log analyzer")
parser.add_argument("--config", dest="config_path")


log_line_re_dict = dict(
REMOTE_ADDR = r'\S+',
REMOTE_USER = r'\S+',
HTTP_X_REAL_IP = r'\S+',
TIME_LOCAL = r'\[.*\]',
URL = r'"(\S+\s)?(?P<url>\S+)(\s\S+)?"',
STATUS = r'\d{3}',
BODY_BYTES_SENT = r'\d+',
HTTP_REFERER = r'".+"',
HTTP_USER_AGENT = r'".+"',
HTTP_X_FORWARDED_FOR = r'".+"',
HTTP_X_REQUEST_ID = r'".+"',
HTTP_X_RB_USER = r'".+"',
REQUEST_TIME = r'(?P<request_time>.*?)',
S = r'\s+'
)

LOG_LINE_REGEX = (r'^{REMOTE_ADDR}{S}{REMOTE_USER}{S}{HTTP_X_REAL_IP}{S}{TIME_LOCAL}{S}{URL}{S}{STATUS}{S}'+
                  r'{BODY_BYTES_SENT}{S}{HTTP_REFERER}{S}{HTTP_USER_AGENT}{S}{HTTP_X_FORWARDED_FOR}{S}'+
                  r'{HTTP_X_REQUEST_ID}{S}{HTTP_X_RB_USER}{S}{REQUEST_TIME}$').format(**log_line_re_dict)

CONFIG_DIR = './config'

REPORT_FILE_TEMPLATE = r'report-%Y.%m.%d.html'

config = {
           "REPORT_SIZE": 1000,
           "REPORT_DIR": "./reports",
           "LOG_DIR": "./log",
           "TEMPLATE": "report.html",
           "MAX_ERROR_RATE": 0.8,
           "LOG_FILE": "log_analyzer.log",
           "LOG_LEVEL": "DEBUG"
}


def find_latest_log(config):
    """
    Find latest log file and check if it's already analyzed

    :param dict config: Log analyzer configuration
    :return: Path to log file, log file exstension, latest log date
    :rtype: tuple
    """
    max_date = date.min
    logpath = ''
    logext = ''
    for filename in os.listdir(config['LOG_DIR']):
        match = re.match(r'^nginx-access-ui\.log-(?P<request_date>\d{8})(?P<ext>(\.gz)?)$',
                         filename)
        if not match:
            continue

        ext = match.group('ext')

        try:
            cur_date = datetime.strptime(match.group('request_date'),'%Y%m%d').date()
            if cur_date > max_date:
                max_date = cur_date
                logpath = filename
                logext = ext
        except ValueError as e:
            logging.error("Incorrect date: %s"%(match.group('request_date')))

    if not logpath or logext not in ['', '.gz']:
        logging.info("No log file detected")
    elif logpath:
        logging.info("Found log: '%s'" % (logpath,))

    return logpath, logext, max_date




def parse(config,logfile,logext):
    """
    Iterate log file and yield parsed url and request_time

    :param config: Log analyzer configuration
    :param logfile: Path to log file
    :param logext: Log file exstension
    :return: url, request_time
    """
    openfunc = gzip.open if logext == '.gz' else open
    with openfunc(os.path.join(config['LOG_DIR'], logfile), "rt", encoding="utf-8") as fp:
        num_errors = 0
        num_lines = 0
        for line in fp:
            match = re.search(LOG_LINE_REGEX, line)
            if match:
                url = match.group('url')
                request_time = float(match.group('request_time'))
                yield url, request_time
            else:
                num_errors += 1
            num_lines += 1
        if num_errors / num_lines > config["MAX_ERROR_RATE"]:
            logging.error("Maximum error rate reached in '%s'" % (logfile,))


def read_config(default_config):
    """
    Parse command line, read config file if exists and merge with the default config

    :param config: Default log analyzer configuration
    :return: Log analyzer configuration
    """

    args = parser.parse_args()

    config_path = os.path.join(CONFIG_DIR,args.config_path if args.config_path else 'config.json')
    try:
        with open(config_path, "r", encoding="utf-8") as fp:
            # Merge configs (config from file has a priority)
            return {**config, **json.load(fp)}
    except IOError as e:
        return default_config

def read_template(template_path):
    '''

    :param template_path: Path to template file
    :return: Template str
    '''
    try:
        with open(config['TEMPLATE'], 'r', encoding='utf-8') as fp:
            return fp.read()
    except IOError as e:
        logging.error("Could not read template file: '%s'. %s" % (config['TEMPLATE'], str(e)))
        return ''

def collect_request_data(config, logpath, logext):
    '''
    Collects parsed request data (number of requests, urls, request time)

    :param config: config dict
    :param logpath: path to parsed log file
    :param logext: log file extension
    :return: urls: dict of urls, time_total: total request time, count_total: total number of requests
    '''
    urls = {}
    # Total request number
    count_total = 0
    # Total request time
    time_total = 0

    for url, request_time in parse(config, logpath, logext):
        time_total += request_time
        count_total += 1
        if url in urls:
            urls[url]['count'] += 1
            urls[url]['time'].append(request_time)
            urls[url]['time_sum'] += request_time
        else:
            urls[url] = {'count': 1, 'time': [request_time], 'time_sum': request_time}

    urls = OrderedDict(sorted(urls.items(),
                              key=lambda key_value: key_value[1]['time_sum'],
                              reverse=True)[:config['REPORT_SIZE']])

    return urls, time_total, count_total

def calc_stats(urls,time_total,count_total):
    '''

    :param urls: OrderedDict
    :param time_total: Total request time
    :param count_total: Total number of requests
    :return: JS-ready statistics for the HTML template
    '''
    table_json = []
    for url, value in urls.items():
        sorted_time = sorted(value['time'])
        len_time = len(sorted_time)
        half_len_time = len_time // 2
        table_json.append({
            'url': url,
            'count': value['count'],
            'count_perc': round(value['count'] / count_total, 6),
            'time_sum': round(value['time_sum'], 4),
            'time_perc': round(value['time_sum'] / time_total, 6),
            'time_avg': round(value['time_sum'] / len_time, 4),
            'time_max': round(sorted_time[-1], 4),
            'time_med': round(sorted_time[half_len_time], 4) if len_time % 2 else \
                round((sorted_time[half_len_time] + sorted_time[half_len_time - 1]) / 2.0, 4)
        })
    return table_json

def create_report(reportdir, reportpath, templ, table_json):
    '''
    Renders template and writes a HTML report file

    :param reportdir: report directory
    :param reportpath: report path
    :param templ: template string
    :param table_json: JSON stats table
    '''

    try:
        if not os.path.isdir(reportdir):
            os.mkdir(reportdir)

        with open(reportpath,'w',encoding='utf-8') as fout:
            fout.write(Template(templ).safe_substitute(table_json=json.dumps(table_json)))
            logging.info("Report succesfully created: '%s'" % (reportpath))
    except IOError as e:
        logging.error("Could not write file: '%s'\n%s"%(reportpath,str(e)))

def main(default_config):

    # Read config file
    config = read_config(default_config)
    if not config:
        return

    logging.basicConfig(filename=config.get('LOG_FILE', None), level=config.get('LOG_LEVEL','DEBUG'),
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')


    templ = read_template(config['TEMPLATE'])
    if not templ:
        return

    logpath, logext, max_date = find_latest_log(config)
    if not logpath:
        # Log file not found
        return

    # Check if report is already created
    reportpath = os.path.join(config['REPORT_DIR'], max_date.strftime(REPORT_FILE_TEMPLATE))
    if os.path.isfile(reportpath):
        logging.info("Report for '%s' already created" % (logpath,))
        return

    urls, time_total, count_total = collect_request_data(config, logpath, logext)

    table_json = calc_stats(urls, time_total, count_total)

    create_report(config['REPORT_DIR'], reportpath, templ, table_json)


if __name__ == "__main__":
    try:
        main(config)
    except BaseException as e:
        logging.exception(str(e))