import os
import dpkt
import socket

def flow_direction(pcap):
    c2s = []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
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
        len_dir = []
        try:
            f = open(file_path, "rb")
            pcap = dpkt.pcap.Reader(f)
            c2s = flow_direction(pcap)
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
                        len_dir.append(len(data))
                    else:
                        len_dir.append(-len(data))

                    if thr >= firstN:
                        break
        except Exception as e:
            print(e)

        print(len_dir)

if __name__ == '__main__':
    data_path = './data'
    protocol_type = ['smb', 'smtp', 'tls_1.2']
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


