#!/usr/bin/env python

import unittest
import textwrap
import snortpager
import StringIO

class AlertParseTest(unittest.TestCase):

    alert_full_format = '[**] [1:10000001:1] ICMP test [**]\
                         [Priority: 0]\
                         01/21-05:14:56.944587 192.168.2.18 -> 184.150.183.114\
                         ICMP TTL:64 TOS:0x0 ID:157 IpLen:20 DgmLen:84\
                         Type:8  Code:0  ID:60162   Seq:0  ECHO\
                         \
                         [**] [1:10000001:1] ICMP test [**]\
                         [Priority: 0]\
                         01/21-05:14:56.961267 184.150.183.114 -> 192.168.2.18\
                         ICMP TTL:57 TOS:0x0 ID:16527 IpLen:20 DgmLen:84\
                         Type:0  Code:0  ID:60162  Seq:0  ECHO REPLY\
                         \
                         [**] [1:10000001:1] ICMP test [**]\
                         [Priority: 0]\
                         01/21-05:14:57.971724 192.168.2.18 -> 184.150.183.114\
                         ICMP TTL:64 TOS:0x0 ID:160 IpLen:20 DgmLen:84\
                         Type:8  Code:0  ID:60162   Seq:1  ECHO\
                         \
                         '
    alert_fast_format_1 = '01/21-05:09:48.809540  [**] [1:10000001:1] ICMP test [**] [Priority: 0] {ICMP} 192.168.2.18 -> 184.150.183.178'
    alert_fast_format_2 = '01/21-05:10:15.652628  [**] [1:10000001:1] ICMP test [**] [Priority: 0] {IPV6-ICMP} fe80::cc1:e6f9:74e0:d69f -> ff02::16'
    alert_fast_format_3 = '01/21-05:09:48.809540  [**] [1:10000001:1] ICMP test [**] [Priority: 0] {ICMP} 192.168.2.18 -> 184.150.183.178'
    
    def setUp(self):
        self.alert_list = []
        
    def tearDown(self):
        self.alert_list = None

    def test_parse_full(self):
        alert_file = StringIO.StringIO(textwrap.dedent(self.alert_full_format))
        line = alert_file.readline()
        for y in range(0,3):
            self.alert_list.append(snortpager.parse_alert_full(alert_file, line))
        self.assertEqual(len(self.alert_list), 3, 'alert_full parsing failed')

    def test_parse_fast(self):
        test1 = snortpager.parse_alert_fast(self.alert_fast_format_1)
        self.assertIsNotNone(test1)
        test2 = snortpager.parse_alert_fast(self.alert_fast_format_2)
        self.assertIsNotNone(test2)
        test3 = snortpager.parse_alert_fast(self.alert_fast_format_3)
        self.assertIsNotNone(test3)

if __name__ == "__main__":
    unittest.main()
