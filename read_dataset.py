import os
import dpkt
import socket
import numpy as np

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

def length_direction_feature(firstN, type, file_name_list):
    # 确定报文前向与后向方向信息
    print("[Info] Start Confirm the direction of {0} protocol packets...".format(type))
    for file_name in file_name_list:
        file_path = os.path.join('./data', file_name)
        print(file_name)
        len_list = []
        try:
            c2s = flow_direction(file_path)
            f = open(file_path, "rb")
            pcap = dpkt.pcap.Reader(f)
            thr = 0
            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                trans = ip.data
                data = trans.data
                if len(data) > 0:
                    thr += 1
                    src = (ip.src, trans.sport)
                    if src == c2s[0]:
                        len_list.append(len(data))
                    else:
                        len_list.append(-len(data))

                    # if thr >= firstN:
                    #     break
        except Exception as e:
            print(e)

        # print(len_list)

        state_dir = {}
        first_len = len_list[0]
        seq = 1
        for i in range(1, len(len_list)):
            if seq not in state_dir.keys():
                state_dir[seq] = []
                state_dir[seq].append(first_len)
            next_len = len_list[i]
            if first_len * next_len > 0:  # 两个报文长度同方向
                state_dir[seq].append(next_len)
                first_len = next_len
            else:  # 两报文长度不同方向
                seq += 1
                first_len = next_len
                if seq not in state_dir.keys():
                    state_dir[seq] = []
                state_dir[seq].append(first_len)

        # for key in state_dir.keys():
        #     if state_dir[key][0] > 0:
        #         print("[Info] Fw: ", end='')
        #     else:
        #         print('[Info] Bw: ', end='')
        #     print(state_dir[key])

        interactive_pktlen = []
        for key in state_dir.keys():
            interactive_pktlen.append(round(np.mean(state_dir[key]), 2))

        print(interactive_pktlen)


if __name__ == '__main__':
    data_path = './data'
    protocol_type = ['smb', 'smtp', 'tls1.2']
    firstN = 30
    protocol_dic = {}
    file_name_list = os.listdir(data_path)
    for file_name in file_name_list:
        for type in protocol_type:
            if type in file_name:
                if type not in protocol_dic.keys():
                    protocol_dic[type] = []
                if file_name not in protocol_dic[type]:
                    protocol_dic[type].append(file_name)

    for type in protocol_dic.keys():
        c2s = length_direction_feature(firstN, type, protocol_dic[type])
