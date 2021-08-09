import dpkt
import os
import socket

def flow_direction(path):
    f = open(path, "rb")
    pcap = dpkt.pcap.Reader(f)
    c2s = []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        # ip = dpkt.ip.IP(buf) # 如果是Raw IP Packet，不存在物理层数据，直接读取IP层数据
        trans = ip.data
        src = (ip.src, trans.sport)
        dst = (ip.dst, trans.dport)
        if trans.dport < 1024 or trans.dport == 8080:  # 协议服务器端口通常小于1024
            c2s = [src, dst]
        elif trans.sport < 1024 or trans.sport == 8080:
            c2s = [dst, src]
        elif trans.sport > trans.dport:  # 如果两个端口均大于1024，则选择较小的一端为服务器端口
            c2s = [src, dst]
        else:
            c2s = [dst, src]
        print("({0}, {1}), ({2}, {3})".format(socket.inet_ntop(socket.AF_INET, c2s[0][0]), c2s[0][1],
                                              socket.inet_ntop(socket.AF_INET, c2s[1][0]), c2s[1][1]))
        # print(c2s)
        break

    return c2s

path = './data/tls1.2 (95).pcap'
c2s = flow_direction(path)
f = open(path, "rb")
pcap = dpkt.pcap.Reader(f)
thr = 0
len_dir = []
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    print('{0}'.format(socket.inet_ntop(socket.AF_INET, ip.src)))
    print('{0}'.format(socket.inet_ntop(socket.AF_INET, ip.dst)))
    trans = ip.data
    data = trans.data
    print(len(data))
    if len(data) > 0:
        thr += 1
        src = (ip.src, trans.sport)
        # print(src)
        if src == c2s[0]:
            len_dir.append(len(data))
        else:
            len_dir.append(-len(data))

print(len_dir)