#!/usr/bin/env python

import re
import argparse
import subprocess
import pygerduty

#TODO: add retro-active option, where we parse all events in file before beginning tail

alert_format = re.compile('\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]')
alert_list = []

def tail(filename):
    p = subprocess.Popen(['tail', '-F', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.stdout, p.stderr

def parse_alert_full(tail_output, line):
    alert = ''
    event_complete = False
    while not event_complete:
        matcher = alert_format.search(line)
        if matcher:
            alert = line
            line = tail_output.readline()
        elif line == '\n':
            event_complete = True
        elif line == '':
            return None
        else:
            alert += line
            line = tail_output.readline()
    return alert
        
def parse_alert_fast(line):
    matcher = alert_format.search(line)
    if matcher:
        return line
    else:
        return None
    
def send_alert(alert, alert_id):
    pager.create_event(args.apikey, alert_id, 'Snort Alert', alert)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Snort-PagerDuty connector')
    parser.add_argument('-f', dest='filename', type=str, help='path to snort alerts file. defaults to /var/log/snort/alert', default='/var/log/snort/alert', required=True)
    parser.add_argument('-k', dest='apikey', type=str, help='PagerDuty API key', required=True)
    parser.add_argument('--alert_fast', action='store_true', help='expect alert_fast format')
    parser.add_argument('--alert_full', action='store_true', help='expect alert_full format')
    args = parser.parse_args()

    if args.alert_fast and args.alert_full:
        print "Choose either alert_full or alert_fast for the Snort alert file format"
        quit(1)
    
    pager = PygerDuty('Snort Alerts for PagerDuty', args.apikey)
    stdout, stderr = tail(args.filename)
    if args.alert_full:
        line = stdout.readline()
        while not alert_format.search(line):
            line = stdout.readline()
        while True:
            alert = parse_alert_full2(stdout, line)
            if alert:
                print alert
            line = stdout.readline()
    elif args.alert_fast:
        line = stdout.readline()
        while True:
            alert = parse_alert_fast(line)
            if alert:
                print alert
            line =  stdout.readline()
            
