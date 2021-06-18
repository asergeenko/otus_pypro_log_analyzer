#!/usr/bin/env python
# -*- coding: utf-8 -*-

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import sys
import os
import logging
import gzip
import re
import json
from datetime import date

from string import Template
from collections import OrderedDict

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
           "REPORT_DIR": "./reprts",
           "LOG_DIR": "./log",
           "TEMPLATE": "report.html",
           "MAX_ERROR_RATE": 0.8,
           "LOG_FILE":"log_analyzer.log"
}


def find_latest_log(config):
    """
    Find latest log file and check if it's already analyzed

    :param dict config: Log analyzer configuration
    :return: Path to log file, log file exstension, path to report file
    :rtype: tuple
    """
    max_date = date.min
    logpath = ''
    logext = ''
    for filename in os.listdir(config['LOG_DIR']):
        match = re.match(r'^nginx-access-ui\.log-(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})(?P<ext>(\.gz)?)$',
                         filename)
        if match:
            day = int(match.group('day'))
            month = int(match.group('month'))
            year = int(match.group('year'))
            ext = match.group('ext')

            try:
                cur_date = date(day=day,month=month,year=year)
                if cur_date > max_date:
                    max_date = cur_date
                    logpath = filename
                    logext = ext
            except ValueError as e:
                logging.error("Incorrect date: %d-%d-%d"%(day,month,year))
            
    # Check if report is already created
    reportpath = os.path.join(config['REPORT_DIR'], max_date.strftime(REPORT_FILE_TEMPLATE))
    if os.path.isfile(reportpath):
        logging.info("Report for '%s' already created"%(logpath,))
        return '','',''
    elif not logpath or logext not in ['','.gz']:
        logging.info("No log file detected")
    return logpath, logext, reportpath


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
    if len(sys.argv) == 3 and sys.argv[1]=='--config':
            config_path = os.path.join(CONFIG_DIR,sys.argv[2])
            try:
                with open(config_path, "r", encoding="utf-8") as fp:
                    # Merge configs (config from file has a priority)
                    user_config = {**config, **json.load(fp)}
            except IOError as e:
                logging.error("Could not read config file: '%s'. %s. Aborting..." % (config_path, str(e)))
                return None
    else:
        user_config = default_config.copy()

    # Check if REPORT_DIR exists
    if not os.path.isdir(user_config['REPORT_DIR']):
        logging.error("Report directory '%s' doesn't exist. Aborting..."%(user_config['REPORT_DIR'],))
        return None

    return user_config


def main(default_config):
    # Read config file
    config = read_config(default_config)
    if not config:
        return

    # Read template from file
    try:
        with open(config['TEMPLATE'], 'r', encoding='utf-8') as fp:
            templ = fp.read()
    except IOError as e:
        logging.error("Could not read template file: '%s'. %s" % (config['TEMPLATE'], str(e)))
        return

    # Total request number
    count_total = 0
    # Total request time
    time_total = 0

    logpath,logext,reportpath = find_latest_log(config)
    if not logpath:
        # Log file not found
        return
    logging.info("Found log: '%s'"%(logpath,))
    urls = {}
    for url, request_time in parse(config, logpath,logext):
        time_total += request_time
        count_total += 1
        if url in urls:
            urls[url]['count'] += 1
            urls[url]['time'].append(request_time)
            urls[url]['time_sum']+=request_time
        else:
            urls[url] = {'count': 1, 'time': [request_time],'time_sum':request_time}

    urls = OrderedDict(sorted(urls.items(),
                              key=lambda key_value: key_value[1]['time_sum'],
                              reverse=True)[:config['REPORT_SIZE']])

    table_json = []
    for url,value in urls.items():
        sorted_time = sorted(value['time'])
        len_time = len(sorted_time)
        half_len_time  = len_time // 2
        table_json.append({
                            'url': url,
                            'count': value['count'],
                            'count_perc': round(value['count'] / count_total,6),
                            'time_sum': round(value['time_sum'],4),
                            'time_perc': round(value['time_sum'] / time_total,6),
                            'time_avg': round(value['time_sum'] / len_time,4),
                            'time_max': round(sorted_time[-1],4),
                            'time_med': round(sorted_time[half_len_time],4) if len_time % 2 else \
                                        round((sorted_time[half_len_time] + sorted_time[half_len_time-1]) / 2.0,4)
        })

    try:
        with open(reportpath,'w',encoding='utf-8') as fout:
            fout.write(Template(templ).safe_substitute(table_json=json.dumps(table_json)))
            logging.info("Report succesfully created: '%s'" % (reportpath))
    except IOError as e:
        logging.error("Could not write file: '%s'\n%s"%(reportpath,str(e)))


if __name__ == "__main__":
    logging.basicConfig(filename=config.get('LOG_FILE', None),level=logging.DEBUG,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    try:
        main(config)
    except BaseException as e:
        logging.exception(str(e))