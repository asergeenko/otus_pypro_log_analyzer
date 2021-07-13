import unittest
import log_analyzer as la
import sys
import os
import logging
import datetime

CONFIG_SAMPLE = {
    "REPORT_SIZE": 2000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "TEMPLATE": "report.html",
    "MAX_ERROR_RATE": 0.8,
    "LOG_FILE":"log_analyzer.log",
    "LOG_LEVEL": "DEBUG"
}



class LogAnalyzerTest(unittest.TestCase):

    #def test_no_config_file(self):
    #    sys.argv[1:]=[]
    #    self.assertEqual(la.read_config(la.config),la.config)


    def test_good_config_file(self):
        sys.argv+=['--config','config.json']
        self.assertEqual(la.read_config('./config/config.json',la.config), CONFIG_SAMPLE)


    def test_no_log(self):
        config = la.read_config('./config/config.json', la.config)
        config['LOG_DIR'] = './test/empty'
        self.assertEqual(la.find_latest_log(config)[0],'')

    def test_bz2_log(self):
        config = la.read_config('./config/config.json', la.config)
        config['LOG_DIR'] = './test/bz2'
        self.assertEqual(la.find_latest_log(config)[0], '')


    def test_plain_log(self):
        config = la.read_config('./config/config.json', la.config)
        config['LOG_DIR'] = './test/plain'
        self.assertEqual(la.find_latest_log(config), ('nginx-access-ui.log-20200831', '', datetime.date(2020,8,31)))


    def test_gz_log(self):
        config = la.read_config('./config/config.json', la.config)
        config['LOG_DIR'] = './test/gz'
        self.assertEqual(la.find_latest_log(config),
                         la.LatestLog('nginx-access-ui.log-20200831.gz', '.gz',
                                      datetime.date(2020,8,31)))

    def test_bad_log(self):
        config = la.read_config('./config/config.json', la.config)
        config['LOG_DIR'] = './test/bad'
        logfile = 'nginx-access-ui.log-20200831'
        logging.basicConfig(filename=config.get('LOG_FILE', None), level=logging.DEBUG,
                            format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')

        request_data = la.collect_request_data(config, la.LatestLog(logfile,'',datetime.date(2020,8,31)), la.parse)

        with open(config['LOG_FILE'],"r") as fp:
            self.assertIn("Maximum error rate reached in '%s'" % (logfile,), fp.readlines()[-1])


if __name__ == '__main__':
    unittest.main()
