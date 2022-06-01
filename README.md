# py_network_sniffer_sender
network packet sender and packet sniffer

CAUC中国民航大学2019级计算机科学与技术专业
网络课程设计第一个模块：Python协议编辑器与Python协议分析器

题目要求：
本模块要求设计实现基于Scapy开发包的协议分析器和协议编辑器。命令行界面数据包发送协议编辑器，实现以太网MAC协议，IP协议，TCP协议，UDP协议，每个协议支持用户编辑全部字段。对于三层及以上的各层协议，均应构造从二层开始的多层数据包。例如编辑TCP数据包，应包括MAC，IP，TCP三层协议。必须通过wireshark捕获到发送的数据包。命令行界面协议分析器，必须支持Ether，ARP，IP，ICMP，TCP，UDP协议，HTTP和DNS至少实现一个，且支持捕获过滤器。

开发环境：
Windows 11 Professional 21H2 22000.652, Python 3.10

