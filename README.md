20230728优化，改为基于python3开发，增加了网站标题展示

【设计思路】


用Nmap做全网端全端口安全监控，用于探测内网或外网大量ip，可极大提升扫描速度

1、使用masscan把ip端口扫描出来后，保存为json格式
2、将IP和端口提取，输入到nmap中扫描，使用多进程方法扫描
3、如果是http的，同时检测Web站点标题并打印展示


【用法】


1、在该python文件的同文件夹下，创建一个scan_ip.txt，可以是IP或ip段，一行行分割
如
10.0.1.0/24
10.2.1.11

2、执行
python nmap_port_scan_withmasscan.py
可以看到输出的结果


