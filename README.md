# snortpager
A small script to tail a Snort (https://www.snort.org/) plain-text alerts file, and send the alerts to the PagerDuty API

usage: snortpager.py [-h] -f FILENAME -k APIKEY [--alert_fast] [--alert_full]

Snort-PagerDuty connector

optional arguments:

  -h, --help    show this help message and exit
  
  -f FILENAME   path to snort alerts file. defaults to /var/log/snort/alert
  
  -k APIKEY     PagerDuty API key
  
  --alert_fast  expect alert_fast format
  
  --alert_full  expect alert_full format
