# 本代码版权归Mengyun199所有，All Rights Reserved (C) 2022-
#####################################################################################################
# 所属域：hanasaki-workstation
# 登录用户：Mengyun Jia
# 机器名称：hanasaki-workstation
# 联系人邮箱：jiamengyun1024@outlook.com
#####################################################################################################
# 创建年份：2022
# 创建人：Mengyun Jia
#####################################################################################################

from scapy.all import *

class MyEth(Packet):
    name="MyEther"
    fields_desc=[DestMACField("dst"),
                 SourceMACField("src"),
                 XShortEnumField("type",0x0800,ETHER_TYPES),
                 IntEnumField("donald" , 1 ,{ 1: "ETH1", 2: "ETH2" , 3: "ETH3" } )]

class MyUDP(Packet):
    name = "MyUDP"
    fields_desc = [ShortEnumField("sport", 53, UDP_SERVICES),
                   ShortEnumField("dport", 53, UDP_SERVICES),
                   ShortField("len", None),
                   XShortField("chksum", None),
                   IntEnumField("donald" , 1 ,{ 1: "UDP1", 2: "UDP2" , 3: "UDP3" } )]

class MyTCP(Packet):
    name = "MyTCP"
    fields_desc = [ShortEnumField("sport", 20, TCP_SERVICES),
                   ShortEnumField("dport", 80, TCP_SERVICES),
                   IntField("seq", 0),
                   IntField("ack", 0),
                   BitField("dataofs", None, 4),
                   BitField("reserved", 0, 3),
                   FlagsField("flags", 0x2, 9, "FSRPAUECN"),
                   ShortField("window", 8192),
                   XShortField("chksum", None),
                   ShortField("urgptr", 0),
                   TCPOptionsField("options", ""),
                   IntEnumField("donald" , 1 ,{ 1: "TCP1", 2: "TCP2" , 3: "TCP3" })]

def eth_editor():		#Ether以太网MAC帧数据包编辑函数
	eth_macsrc = input("source mac address: ")
	eth_macdst = input("destination mac address: ")
	type = input("type: ")
	try:		#异常处理防止用户输入错误的类型数据
		eth_type = int(type,16)
	except :		#若用户输入无效则提示无效数据并退出程序
		print("invalid mac address detected\nscript exiting...")
		exit()
	eth_packet = Ether(dst = eth_macdst, src = eth_macsrc, type = eth_type)
	eth_packet.show()
	return eth_packet

def ip_editor():		#IP协议数据包编辑函数
	ip_version = input("ip protocol version: ")
	ip_ihl = input("header length: ")
	ip_tos = input("type od service: ")
	ip_len = input("total length: ")
	ip_id = input("identifier: ")
	ip_flags = input("flags(DF/MF): ")
	ip_frag  = input("fragment offset: ")
	ip_ttl = input("ttl: ")
	ip_src = input("source ip address: ")
	ip_dst = input("destination ip address: ")
	ip_packet = IP(version = ip_version,ihl = ip_ihl,tos = ip_tos,len = ip_len,id = ip_id,flags = ip_flags,frag = ip_frag,ttl = ip_ttl,proto = 6,src = ip_src,dst = ip_dst)
	return ip_packet

def tcp_editor():		#TCP协议数据包编辑函数
	tcp_sport = input("source port: ")
	tcp_dport = input("destination port: ")
	tcp_seq = input("sequence: ")
	tcp_ack = input("acknowledge: ")
	tcp_dataofs = input("data offset: ")
	tcp_reserved = input("reserved: ")
	tcp_flags = input("flags: ")
	tcp_window = input("window: ")
	tcp_urgptr = input("urgent pointer: ")
	tcp_packet = TCP(sport = tcp_sport,dport = tcp_dport,seq = tcp_seq,ack = tcp_ack,dataofs = tcp_dataofs,reserved = tcp_reserved,flags = tcp_flags,window = tcp_window,urgptr = tcp_urgptr)
	return tcp_packet

def udp_editor():		#UDP协议数据包编辑函数
	udp_sport = input("source port: ")
	udp_dport = input("destination port: ")
	udp_len = input("total length: ")
	udp_packet = UDP(sport = udp_sport,dport = udp_dport,len = udp_len)
	return udp_packet


# PROGRAM START HERE
# 用户选择模式并根据用户的输入进入协议编辑器或协议分析器
mode = input("select a mode\n1. packet editor\n2. packet sniffer\n\nselection: ")
print("\n")

if mode == '1':		#数据包发送（协议编辑器）
	type = input("select a protocol\n1. Ether\n2. IP\n3. TCP\n4. UDP\nselection: ")
	print("\n")

	#调用已定义的函数进行协议编辑与数据包的组装
	if type == '1' :
		packs = eth_editor()

	elif type == '2' :
		packs = (eth_editor()/ip_editor())

	elif type == '3' :
		packs = (eth_editor()/ip_editor()/tcp_editor())

	elif type == '4' :
	    packs = (eth_editor()/ip_editor()/udp_editor())

	else:
		#无效输入直接退出程序
		print("invalid selection detected\nscript exiting...")
		exit()
	
	#发送组装好的数据包
	sendp(packs)

elif mode == '2':		#数据包捕获及分析（协议分析器）

	#用户选择捕获数据包的数量
	sniff_count = int(input("input number of packets to sniff: "))
	print("\n")

	#用户选择过滤器
	filter_num = input("select a protocol:\n1. Ether\n2. ARP\n3. IP\n4. TCP\n5. ICMP\n6. UDP\n7. DNS\n\nselection: ")
	print("\n")

	#按照用户的选择设置过滤器的内容
	if filter_num == '1':
		sniff_filter = ""

	elif filter_num == '2':
		sniff_filter = "arp"

	elif filter_num == '3':
		sniff_filter = "ip"

	elif filter_num == '4':
		sniff_filter = "tcp"

	elif filter_num == '5':
		sniff_filter = "icmp"

	elif filter_num == '6':
		sniff_filter = "udp"

	elif filter_num == '7':
		sniff_filter = "port 53"

	else:
		#无效输入直接退出程序
		print("invalid selection detected\nscript exiting...")
		exit()

	#输出格式"lambda x:x.summary()"为借鉴他人代码，目前不懂其原理
	packets = sniff(prn = lambda x:x.summary(), count = sniff_count, filter = sniff_filter)

	#以下代码用来分析已捕获的数据包
	while (1):
		#用户选择需要分析的数据包编号后记录在变量i中，若用户输入0则退出
		i=int(input("select a packet to analyze(input a number, 0 to cancel): "))

		if i == 0:
			#用户输入0提示用户并退出脚本执行
			print("user exit operation detected\nscript exiting...")
			exit()

		#显示分析对应编号的数据包内容
		packets[i-1].show()

else:
	#无效输入直接退出程序
	print("invalid selection detected\nscript exiting...")
	exit()

