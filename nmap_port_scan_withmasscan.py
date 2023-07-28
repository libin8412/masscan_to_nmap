# encoding: utf-8
import json
import sys
from libnmap.process import NmapProcess
from libnmap.reportjson import ReportDecoder,ReportEncoder
from libnmap.parser import NmapParser,NmapParserException
import time
import multiprocessing
import os
import json
import requests
import chardet
import re

# 处理端口状态
global_port_states =['open']
# 使用masscan扫描,存储扫描结果，以作为nmap扫描的输入源
if os.path.exists('test_json4.json'):
    os.remove('test_json4.json')
os.system('/Users/larry/Program/masscan/bin/masscan -iL scan_ip.txt -p1-65535 -oJ test_json4.json --rate 50000')
# os.system('masscan -iL scan_ip4.txt -pU:1-65535 -oJ test_json4_udp.json --rate 10000') udp扫描

# 定义函数，用于进行扫描
def do_nmap_scan(scan_ip_list, scan_port):
    # nmap自定义UA，避免被WAF检测到
    nmap_proc = NmapProcess(scan_ip_list, options='-sT -sV -p ' + str(scan_port) + ' -script-args http.useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36"')
    nmap_proc.run()
    nmap_repot = NmapParser.parse(nmap_proc.stdout)
    for host in nmap_repot.hosts:
        for serv in host.services:
            if serv.state in global_port_states:
                if serv.service == "http":
                    scan_url = 'http://' + host.address + ':' + str(serv.port)
                    Title(scan_url)
                else:
                    print('scan_host is %s,scan result is %s|%s|%s|%s|%s' \
                          % (host.address, str(serv.port), serv.protocol, serv.state, serv.service, serv.banner))



# 获取网站标题
def Title(scan_url_port):
    try:
        r = requests.get(scan_url_port, timeout=5, verify=False, stream=True)
        # 获取网站的页面编码
        if 'Content-Length' in r.headers.keys() and int(r.headers['Content-Length']) > 50000:
            print('[*]主机 ' + scan_url_port + ' 端口服务为：' + '大文件')
        else:
            r_detectencode = chardet.detect(r.content)
            actual_encode = r_detectencode['encoding']
            response = re.findall(u'<title>(.*?)</title>', r.content.decode(actual_encode), re.S)
            if response == []:
                pass
            else:
                # 将页面解码为utf-8，获取中文标题
                res = response[0]
                banner = r.headers['server']
                print(
                    scan_url_port + '\t' + "".join(banner.split()) + '\t' + ''.join(res.split()) + '\t' + str(
                        r.status_code) + '\t' + str(len(r.content)))

    except Exception as e:
        pass


# 定义扫描开始时间
time_start = time.time()


if __name__ == "__main__":
    # 引入多进程
    pool = multiprocessing.Pool(8)
    with open('test_json4.json', 'r') as file:
        # masscan有一个坑，也就是输出的json格式有问题，需要去掉最后有问题的“,”号，否则json不解析
        str1 = file.read()
        str2 = str1[:-4] + str1[-3:]
        data = json.loads(str2)
        for i in range(len(data)):
            scan_ip_list = data[i]['ip']
            scan_port = data[i]['ports'][0]['port']
            pool.apply_async(do_nmap_scan, args=(str(scan_ip_list), scan_port,))
    pool.close()
    pool.join()
    print('扫描时间为%s秒' % (time.time() - time_start))
