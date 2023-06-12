
from multiprocessing.pool import ThreadPool as Pool #多线程用
import socket, os, datetime, re #三个函数要用到re
socket.setdefaulttimeout(2) #最大每个链接反DNS检查的等待秒数

fltr_urls = ["/fen1.jpg", "/admin", "/xmlrpc.php"]
pool_max    = 85 #pool_max = 15 #设定多线程并发数量，由于socket.getfqdn单线程太慢，同时又不占用资源的解决方法

def five_min_ago(): #获取5分钟前的时间则引用此Function
    from datetime import timedelta #计算时间差
    from dateutil import parser #转换时间格式
    return datetime.datetime.now() - timedelta(minutes=5000)
five_mins_ago = five_min_ago()

def logging_nvtime(line): #获取第line行IP的log时间，引用此函数时要附带行数参数
    from dateutil import parser
    log_time_str   = re.search(r"\[(.*?)\]", line).group(1)
    log_time_aware = parser.parse(log_time_str.replace(":", " ", 1))
    return log_time_aware.replace(tzinfo=None)

#if " 404 " in line and (logging_nvtime(line) >= five_mins_ago) and (re.search(r"\d+\.\d+\.\d+\.\d+", line)) and (line not in ip_dict):
#    ip_dict[ip] += 1
#else:
#    ip_dict[ip] = 1

#def lowerpriority(): #防止占用服务器太多算力用
#    if os.name == 'nt': #用CMD的wmic命令降低Windows系统进程优先级
#        os.system("wmic process where processid=\""+str(os.getpid())+"\" CALL setpriority \"below normal\"")
#    else: #降低Unix/Linux系统进程优先级
#        os.nice(1)
#lowerpriority()

#wk_path   = "D:\\BtSoft\\wwwlogs\\" #设定工作路径位置(含ipFile, ipBlock, ipSafe三个文本文档)
wk_path   = "D:\\Desktop\\wwwlogs\\"
wk_files  = [file for file in os.listdir(wk_path) if os.path.getsize(wk_path+file) > 0 and file.endswith("access.log")] #过滤掉空文件，非*access.log文件
deny_file = "D:\\BtSoft\\apache\\conf\\deny.conf" #设定拦截IP文件位置
#deny_file = "D:\\Desktop\\conf\\deny_test.conf" #设定拦截IP文件位置
safe_file = "D:\\BtSoft\\apache\\conf\\allow.conf.txt" #设定安全IP文件位置, 不一定要用做白名单, 单纯降低此脚本工作量也可行
#safe_file = "D:\\Desktop\\conf\\allow_test.txt"
open(deny_file, "a"); open(safe_file, "a")  #文件不存在则临时创建
#将所有要导入处理的文件做成列表，然后下面用循环遍历wk_path+wk_files[file或file_check]的内容

for file_check in range (0, len(wk_files)):
    if os.path.isfile(wk_path+wk_files[file_check]) == False: #保证导入IP列表的文件存在
        raise Exception(f"× 文件缺失或检测到*access.log同名文件夹: {wk_path+wk_files[file_check]}")
        exit
print("√ 文件初查完毕，所有要导入的文件均正常")

def RDNS_lookup(a_lookup): #以ip做循环变量名, 从ipRDNS词典为范围逐个调用关键词
    try:
        print(f"? 正在通过反DNS检查IP {a_lookup}......")
        if socket.getfqdn(a_lookup) != a_lookup:
            ipRDNS_dict.update({a_lookup: True})#由于socket.getfqdn在找不到FQDN会返回输入的IP地址, 所以将两信息不等的情况视为发现FQDN网址; 发现改False为True
    except socket.timeout:
        print("! 找不到FQDN, 跳过......")

def get_ipv4(ip_input): #get_ipv4一共要处理两批次的IP地址，一次是ipPrev，二次是ipFile，输入的内容是str，不是list
    print(f"? 待过滤IP地址: {ip_input}")
    ipv4_filter = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    return ipv4_filter.search(ip_input).group() #过滤掉除了ipv4地址之外的部分

#get_ipv4("192.168.7.7")
with open(deny_file, "r") as ipBlock, open(safe_file, "r") as ipSafe:
    #ipBlock: 已知拦截列表(暂不打开), 用于跳过计算已拦截的内容
    #ipSafe:  已知安全列表(暂不打开), 用于跳过计算已测过的内容
    #ipPrev:  已知所有旧列表(ipBlock+ipSafe)
    ipPrev = (ipBlock.readlines()[-800:]+ipSafe.readlines()[-200:]) #读取ipBlock+ipSafe两个文本, 分成列表后组合出"已处理列表"
    ipNEm1 = list(filter(("").__ne__, ipPrev)) #删除组合过程中可能会产生，包括log空行可能造成的列表空项
    ipStrp = [ip[11:26] for ip in ipNEm1] #将多余信息(deny from)删除
    ipNEm2 = list(filter(("").__ne__, ipStrp)) #删除文本编辑所产生的列表空项
    ipNDp1 = list(dict.fromkeys(ipNEm2)) #临时转换为词典, 初次消除重复项
    ipADDR = [get_ipv4(ip_input) for ip_input in ipNDp1] #确认log中的每个项目里都有IP地址, 以过滤掉不能用的行
    ipPrev = [ip for ip in ipADDR if ip != "fail"] #ipNDp2
    del ipNEm1, ipStrp, ipNEm2, ipNDp1, ipADDR

def ipPrep(rdns_work, ipPrev): #准备出要RDNS的IP列表, 一次只导入一个ipFile(access.log), 内置循环会处理其中的所有ip
    with open(wk_path+rdns_work, "r") as ipFile: #为在进程出错的情况下顺利关闭文件而使用了with-open语句
        #ipFile:  新增要处理的ip列表
        ipFile = ipFile.readlines()[-1000:] #将输入文本的换行符(每行一个IP的格式)为列表制表分割线分割 print("Debug ipFile: "+ipFile[0])
        ipN5mn = [ip for ip in ipFile if (logging_nvtime(ip) >= five_mins_ago)] #过滤出5分钟前的ip print("Debug ipN5mn: "+ipN5mn[0])
        ipY404 = [ip for ip in ipN5mn if " 404 " in ip] #过滤出非404状态的ip print("Debug ipY404: "+ipY404[0])
        ipNEmp = list(filter(("").__ne__, ipY404)) #清除因为get_ipv4过滤而产生的空项
        ipfURL = [ip for ip in ipNEmp if ip not in fltr_urls] #过滤掉fltr_urls中的网址
        ipStrp = [ip[0:15] for ip in ipfURL] #将多余信息删除
        ipNDp1 = list(dict.fromkeys(ipStrp)) #临时转换为词典, 初次消除重复项
        ipADDR = [get_ipv4(ip_input) for ip_input in ipNDp1] #将输入的文本过滤出IP地址
        ipPass = [ip for ip in ipADDR if ip != "fail"] #过滤掉get_ipv4函数无法识别的IP地址
        ipNews = [ip for ip in ipPass if ip not in ipPrev] #for循环制表+if过滤掉以前跑过的ip地址
        ipNDp2 = list(dict.fromkeys(ipNews)) #临时转换为词典来消除重复项
    return ipNDp2

ipNDp2 = []
ipRDNS_dict = {}

for rdns_work in wk_files: #通过多线程池的for循环进行RDNS检查
    ipNDp2 += ipPrep(rdns_work, ipPrev)
    ipRDNS_dict.update(dict.fromkeys(ipNDp2, False)) #为降低文件读写次数而先处理所有的IP地址再一并导出而建立词典. 例: {'219.100.37.1': False, '109.252.170.221': False, '219.100.37.206': False, '211.221.182.96': False, '3.93.139.87': False, '185.175.230.248': False, '6.6.6.6': False, '2a04:4e42:200::175': False, '151.101.128.175': False, '151.106.42.33': False, '162.210.199.140': False, '135.0.214.75': False}

    loop_max = len(ipRDNS_dict)
    pool     = Pool(pool_max)

    for a_lookup in range(0, loop_max):
        pool.apply_async(RDNS_lookup, (list(ipRDNS_dict.keys())[a_lookup],))

    pool.close()
    pool.join()

ipRDNS_list = list(ipRDNS_dict.items()) #词典没法用数字顺序找, 所以转换到列表
ipRDNS_list = [list(tuples) for tuples in ipRDNS_list] #词典默认将内容转换为tuples, 而tuples没法用数字顺序找, 所以列表内的tuples要转换为列表
#print(ipRDNS_list)

#realBlockList = [ipData for ipData[0] in ipRDNS_list if ipData[1] == True]
#realSafeList  = [ipData for ipData[0] in ipRDNS_list if ipData[1] == False]
blockList = []
safeList = []
for ipData in ipRDNS_list:
    if ipData[1] == True:
        blockList.append(ipData[0])
    else:
        safeList.append(ipData[0])

with open(deny_file, "a") as ipBlock, open(safe_file, "a") as ipSafe:
    for each_line in blockList:
        ipBlock.write("Deny from %s\n" % each_line)
    for each_line in safeList:
        ipSafe.write("Allow from %s\n" % each_line)
    ipBlock.write("\n")
    ipSafe.write("\n")

print(f"√ 检测完成, 文件已输出到 {deny_file}, 及 {safe_file}")
        

