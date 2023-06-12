#支持IPv6
from multiprocessing.pool import ThreadPool as Pool #多线程用
import socket, os
socket.setdefaulttimeout(2) #最大每个链接反DNS检查的等待秒数
#work_path="D:\\Desktop\\" #设定工作路径位置(含ipFile, ipBlock, ipSafe)
work_path="C:\\Users\\Administrator\\Desktop\\"
#pool_max = 15 #设定多线程并发数量
pool_max = 55

if os.path.isfile(work_path+"ip list.txt") == False: #保证导入IP列表的文件存在
    raise Exception("× 文件缺失: "+work_path+"ip list.txt")
    exit

def lowerpriority():
    if os.name == 'nt': #降低Windows系统进程优先级
        os.system("wmic process where processid=\""+str(os.getpid())+"\" CALL setpriority \"below normal\"")
    else: #降低Unix/Linux系统进程优先级
        os.nice(1)

lowerpriority() #运行降低进程优先级的函数

def ipPrep(work_path): #为了在进程出错的情况下顺利关闭文件而使用了with-open语句
    open(work_path+"ip block.txt", "a") #不存在则临时创建
    open(work_path+"ip safe.txt", "a")  #不存在则临时创建
    with open(work_path+"ip list.txt", "r") as ipFile, open(work_path+"ip block.txt", "r") as ipBlock, open(work_path+"ip safe.txt", "r") as ipSafe:
        #ipFile:  新增要处理的ip列表
        #ipBlock: 已知拦截列表(暂不打开), 用于跳过计算已拦截的内容
        #ipSafe:  已知安全列表(暂不打开), 用于跳过计算已测过的内容
        #ipPrev:  已知所有旧列表(ipBlock+ipSafe)
        ipFile = ipFile.read().split("\n") #读取ipFile, 将输入文本的换行符(每行一个IP的格式)为列表制表分割线分割
        ipPrev = (ipBlock.read()+ipSafe.read()).split("\n") #读取ipBlock+ipSafe两个文本, 分成列表后组合
        ipPrev = list(filter(("").__ne__, ipPrev)) #删除组合过程中可能会产生的空列表项
        ipNDup = [ip for ip in ipFile if ip not in ipPrev] #for循环制表+if过滤
        return ipNDup

ipNDup      = ipPrep(work_path)
print("√ 从工作路径获取并过滤出的待处理列表为: "+str(ipNDup))

ipRDNS_dict = dict.fromkeys(ipNDup, False) #为降低文件读写次数而先处理所有的IP地址再一并导出而建立词典. 例: {'219.100.37.1': False, '109.252.170.221': False, '219.100.37.206': False, '211.221.182.96': False, '3.93.139.87': False, '185.175.230.248': False, '6.6.6.6': False, '2a04:4e42:200::175': False, '151.101.128.175': False, '151.106.42.33': False, '162.210.199.140': False, '135.0.214.75': False}

def RDNS_lookup(a_lookup): #以ip做循环变量名, 从ipRDNS词典为范围逐个调用关键词
    try:
        print("? 正在检查IP "+a_lookup+"......")
        if socket.getfqdn(a_lookup) != a_lookup:
            ipRDNS_dict.update({a_lookup: True})#由于socket.getfqdn在找不到FQDN会返回输入的IP地址, 所以将两信息不等的情况视为发现FQDN网址; 发现改False为True
    except socket.timeout:
        print("! 找不到FQDN, 跳过......")

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

with open(work_path+"ip block.txt", "a") as ipBlock, open(work_path+"ip safe.txt", "a") as ipSafe:
    for each_line in blockList:
        ipBlock.write("%s\n" % each_line)
    for each_line in safeList:
        ipSafe.write("%s\n" % each_line)
    ipBlock.write("\n")
    ipSafe.write("\n")

print(f"√ 检测完成, 文件已输出到 {work_path}ip block.txt, 及 {work_path}ip safe.txt")
        

