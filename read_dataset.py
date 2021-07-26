import os
import dpkt


data_path = ''
file_name_list = os.listdir(data_path)
for file_name in file_name_list:
    file_path = os.path.join(data_path, file_name)
    try:
        f = open(file_path, 'rb')
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            trans = ip.data
            data = trans.data



    except Exception as e:
        print(e)


