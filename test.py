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
        # print("({0}, {1}), ({2}, {3})".format(socket.inet_ntop(socket.AF_INET, c2s[0][0]), c2s[0][1],
        #                                       socket.inet_ntop(socket.AF_INET, c2s[1][0]), c2s[1][1]))
        break
    return c2s

path = './data/smtp (750).pcap'
c2s = flow_direction(path)
f = open(path, "rb")
pcap = dpkt.pcap.Reader(f)
thr = 0
len_dir = []
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    # print('{0}'.format(socket.inet_ntop(socket.AF_INET, ip.src)))
    # print('{0}'.format(socket.inet_ntop(socket.AF_INET, ip.dst)))
    trans = ip.data
    data = trans.data
    if len(data) > 0:
        thr += 1
        src = (ip.src, trans.sport)
        # print(src)
        if src == c2s[0]:
            len_dir.append(len(data))
        else:
            len_dir.append(-len(data))

len_dir = [50, 100, 300, -85, 24, -26, 24, -46, 40, -47, -30, -50, -65, 38, 40, 60, -58, -37, 6, -50, -22, 1024, 279, -19, 6, -24]
print(len_dir)
state_dir = {}
first_len = len_dir[0]
seq = 1
for i in range(1, len(len_dir)):
    if seq not in state_dir.keys():
        state_dir[seq] = []
        state_dir[seq].append(first_len)
    next_len = len_dir[i]
    if first_len * next_len > 0: # 两个报文长度同方向
        state_dir[seq].append(next_len)
        first_len = next_len
    else: # 两报文长度不同方向
        seq += 1
        first_len = next_len
        if seq not in state_dir.keys():
            state_dir[seq] = []
        state_dir[seq].append(first_len)

for key in state_dir.keys():
    print(key, end='')
    print(state_dir[key])