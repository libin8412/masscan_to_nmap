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

# 全局扫描参数
# global_options = '-sT -P0 -sV -O --script=banner -p T:21-25,80-89,110,143,443,513,873,1080,1433,1521,1158,3306-3308,3389,3690,5900,6379,7001,8000-8090,9000,9418,27017-27019,50060,111,11211,2049'
# global_options ='-sT -sV -p 445 -script-args http.useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36"'
# global_options ='-sT -sV -p 1-65535 -script-args http.useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36"'

# 处理端口状态
global_port_states =['open']

# 使用masscan扫描,存储扫描结果，以作为nmap扫描的输入源
if os.path.exists('test_json4.json'):
    os.remove('test_json4.json')
os.system('masscan -iL scan_ip2.txt -p1-65535 -oJ test_json4.json --rate 10000')
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
                print 'scan_host is %s,scan result is %s|%s|%s|%s|%s'\
                      % (host.address, str(serv.port), serv.protocol, serv.state, serv.service, serv.banner)
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
        for i in xrange(len(data)):
            scan_ip_list = data[i]['ip']
            scan_port = data[i]['ports'][0]['port']
            pool.apply_async(do_nmap_scan, args=(str(scan_ip_list), scan_port,))
    pool.close()
    pool.join()
    print '扫描时间为%s秒' % (time.time() - time_start)



