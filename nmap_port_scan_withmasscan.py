# encoding: utf-8
import json
import sys
from time import sleep
from libnmap.process import NmapProcess
from libnmap.reportjson import ReportDecoder,ReportEncoder
from libnmap.parser import NmapParser,NmapParserException
import MySQLdb
import time
import multiprocessing
import os
import json


# 数据库操作类
class mymysql:
    def __init__(self, db, host, user, passwd, port=3306):
        self.config = {'db': db,
                       'host': host,
                       'user': user,
                       'passwd': passwd,
                       'port': port,
                       'charset': 'utf8',
                       'unix_socket': '/tmp/mysql.sock'
                       }
        self.conn = MySQLdb.connect(**self.config)
        self.cursor = self.conn.cursor()

    # data = [(x,y,z),(a,b,c)]格式,columns=(column1,column2,column3) tuple or list
    def insert(self, table, columns, data):
        values = []
        for x in xrange(len(data[0])):
            values.append("%s")
        sqli = "insert into " + table + "(" + ",".join(columns) + ") values(" + ",".join(values) + ")"
        self.cursor.executemany(sqli, data)
        self.conn.commit()

    def minsert(self, table, columns, data):
        c = 0
        data_tmp = [1]
        while data_tmp:
            data_tmp = data[c * 50000:c * 50000 + 50000]
            if data_tmp:
                self.insert(table, columns, data_tmp)
            c = c + 1

            # qcolumn = (a,b,c)格式

    def query(self, table, qcolumn, wcolumn=1, wvalue=1):
        sqlq = "select " + ",".join(qcolumn) + " from %s where %s='%s'" % (table, wcolumn, wvalue)
        self.cursor.execute(sqlq)
        data = self.cursor.fetchall()
        return data

    def delete(self, table, column, value):
        sqld = "delete from %s where %s='%s'" % (table, column, value)
        self.cursor.execute(sqld)
        self.conn.commit()

        # data =[(column1,value1,wcolumn1,wvalue1)]

    def update(self, table, data):
        values = []
        for x in xrange(len(data)):
            values.append((data[x][1], data[x][3]))
        sqlu = "update " + table + " set " + data[0][0] + "=%s where " + data[0][2] + "=%s"
        self.cursor.executemany(sqlu, values)
        self.conn.commit()

    # columns= {"set":("column1","column2","column3"),"where":"column4"}
    # data = (1,2,3,4),顺序与上述columns对齐，其中最后一个值为where条件
    def mupdate(self, table, columns, data):
        sets = []
        for x in columns['set']:
            x = x + '=%s'
            sets.append(x)
        sqlu = "update " + table + " set " + ','.join(sets) + " where " + columns['where'] + "=%s"
        self.cursor.executemany(sqlu, data)
        self.conn.commit()

    def execsql(self, sql):
        self.cursor.execute(sql)
        data = self.cursor.fetchall()
        return data

    # self.conn.commit()

    def __del__(self):
        self.cursor.close()
        self.conn.close()

# 创建数据库对象
mysql_object = mymysql('blog', '127.0.0.1', 'root', 'a2fddsec', port=3306)

# 用于插入scan_scan_port表中
columns_port = ('status', 'ip', 'port', 'service','product','product_version','scripts_results','date_now')

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



