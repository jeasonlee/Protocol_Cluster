import os
import dpkt
import socket

def packets_direction(datapath):
    # 确定报文前向与后向方向信息
    print("\nStart Split Forward and Backward Packets...")
    file_name_list = os.listdir(datapath)
    for file_name in file_name_list:
        try:
            file_path = os.path.join(datapath,file_name)
            print(file_path)
            f = open(file_path, "rb")
            pcap = dpkt.pcap.Reader(f)

            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                trans = ip.data
                src = (ip.src, trans.sport)
                dst = (ip.dst, trans.dport)
                if trans.dport < 1024 or trans.dport == 8080: # 协议服务器端口通常小于1024
                    c2s = [src, dst]
                elif trans.sport < 1024 or trans.sport == 8080:
                    c2s = [dst, src]
                elif trans.sport > trans.dport: # 如果两个端口均大于1024，则选择较小的一端为服务器端口
                    c2s = [src, dst]
                else:
                    c2s = [dst, src]

                print("({0}, {1}), ({2}, {3})".format(socket.inet_ntop(socket.AF_INET, c2s[0][0]), c2s[0][1],
                                                      socket.inet_ntop(socket.AF_INET, c2s[1][0]), c2s[1][1]))
                break

        except Exception as e:
            print(e)


if __name__ == '__main__':
    data_path = './data'
    packets_direction(data_path)


