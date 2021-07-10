import unittest
import log_analyzer as la
import sys
import os
import logging

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
        self.assertEqual(la.read_config(la.config), CONFIG_SAMPLE)


    def test_no_log(self):
        config = la.read_config(la.config)
        config['LOG_DIR'] = './test/empty'
        self.assertEqual(la.find_latest_log(config)[0],'')

    def test_bz2_log(self):
        config = la.read_config(la.config)
        config['LOG_DIR'] = './test/bz2'
        self.assertEqual(la.find_latest_log(config)[0], '')


    def test_plain_log(self):
        config = la.read_config(la.config)
        config['LOG_DIR'] = './test/plain'
        self.assertEqual(la.find_latest_log(config), ('nginx-access-ui.log-20200831', '', os.path.join(config['REPORT_DIR'],'report-2020.08.31.html')))


    def test_gz_log(self):
        config = la.read_config(la.config)
        config['LOG_DIR'] = './test/gz'
        self.assertEqual(la.find_latest_log(config), ('nginx-access-ui.log-20200831.gz', '.gz', os.path.join(config['REPORT_DIR'],'report-2020.08.31.html')))

    def test_bad_log(self):
        config = la.read_config(la.config)
        config['LOG_DIR'] = './test/bad'
        logfile = 'nginx-access-ui.log-20200831'
        logging.basicConfig(filename=config.get('LOG_FILE', None), level=logging.DEBUG,
                            format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
        for line in la.parse(config, logfile, ''):
            pass
        with open(config['LOG_FILE'],"r") as fp:
            self.assertIn("Maximum error rate reached in '%s'" % (logfile,), fp.readlines()[-1])

    def test_already_parsed(self):
        config = la.read_config(la.config)
        config['LOG_DIR'] = './test/plain'
        config['REPORT_DIR'] = './test/reports'

        logging.basicConfig(filename=config.get('LOG_FILE', None), level=logging.DEBUG,
                            format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
        la.find_latest_log(config)

        with open(config['LOG_FILE'],"r") as fp:
            self.assertIn("Report for '%s' already created" % ('nginx-access-ui.log-20200831',), fp.readlines()[-1])


if __name__ == '__main__':
    unittest.main()
