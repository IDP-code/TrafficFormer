import os,sys
import random
import shutil
import binascii
import scapy.all as scapy
from functools import reduce
from flowcontainer.extractor import extract
from utils import *
from tqdm import tqdm
import multiprocessing as mp
import traceback

def user_excepthook(tp, val, tb):
    # print the exception to standard error
    traceback.print_exc()

# Semantic lossless enhancement
def enhancement(packets, is_addr=True, is_port=True,):
    # IP6 FLOWLABEL,src,dst
    # IP：IPID，src, dst
    # TCP: seq, ack, sport, dport, 
    # UDP: sport, dport,
    if not hasattr(packets[0],'type'): # some datasets do not have ether header
        new_packets = scapy.PacketList()
        for i in range(len(packets)):
            if packets[i].src == packets[0].src: # ICMP
                # create a ether header
                ether = scapy.Ether(src="00:00:00:00:00:00", dst="ff:ff:ff:ff:ff:ff", type=0x0800)
            else:
                ether = scapy.Ether(src="ff:ff:ff:ff:ff:ff", dst="00:00:00:00:00:00", type=0x0800)
            packet = ether/packets[i]
            new_packets.append(packet)
    packets = new_packets
    first_forward_packet = packets[0].copy()
    for packet_index in range(len(packets)):
        if packets[packet_index].src != first_forward_packet.src:
            first_backward_packet = packets[packet_index].copy()
            break
    if first_forward_packet.type == 0x0800:
        replace_src = random_ipv4()
        replace_dst = random_ipv4()
        replace_src_id = random_field(16)
        replace_dst_id = random_field(16)
        if first_forward_packet.payload.proto == 6:
            replace_sport = random_field(16)
            replace_dport = random_field(16)
            replace_src_seq = random_field(32)
            replace_dst_seq = random_field(32)
        elif first_forward_packet.payload.proto == 17:
            replace_sport = random_field(16)
            replace_dport = random_field(16)

    elif first_forward_packet.type == 0x86dd:
        replace_src = random_ipv6()
        replace_dst = random_ipv6()
        replace_src_flowlabel = random_field(20)
        replace_dst_flowlabel = random_field(20)
        if first_forward_packet.payload.nh == 6:
            replace_sport = random_field(16)
            replace_dport = random_field(16)
            replace_src_seq = random_field(32)
            replace_dst_seq = random_field(32)
        elif first_forward_packet.payload.nh == 17:
            replace_sport = random_field(16)
            replace_dport = random_field(16)

    for packet_index in range(len(packets)):
        if packets[packet_index].src == first_forward_packet.src: #forward
            if is_addr:
                packets[packet_index].payload.src = replace_src
                packets[packet_index].payload.dst = replace_dst
            if packets[packet_index].type == 0x0800:
                if first_forward_packet.payload.id!=0: 
                    packets[packet_index].payload.id =  replace_src_id + (packets[packet_index].payload.id - first_forward_packet.payload.id)
                    packets[packet_index].payload.id %= 2**16
                #print("forward: ",packets[packet_index].payload.id)
                if packets[packet_index].payload.proto == 6:
                    if is_port:
                        packets[packet_index].payload.payload.sport = replace_sport
                        packets[packet_index].payload.payload.dport = replace_dport
                    packets[packet_index].payload.payload.seq = replace_src_seq + (packets[packet_index].payload.payload.seq - first_forward_packet.payload.payload.seq)
                    if not ("S" in packets[packet_index].payload.payload.flags and packets[packet_index].payload.payload.ack==0):
                        packets[packet_index].payload.payload.ack = replace_dst_seq + (packets[packet_index].payload.payload.ack - first_backward_packet.payload.payload.seq)
                    packets[packet_index].payload.payload.seq %= 2**32
                    packets[packet_index].payload.payload.ack %= 2**32
                elif packets[packet_index].payload.proto == 17:
                    if is_port:
                        packets[packet_index].payload.payload.sport = replace_sport
                        packets[packet_index].payload.payload.dport = replace_dport

            elif packets[packet_index].type == 0x86dd:
                packets[packet_index].payload.fl =  replace_src_flowlabel + (packets[packet_index].payload.fl - first_forward_packet.payload.fl)
                packets[packet_index].payload.fl %= 2**20
                if packets[packet_index].payload.nh == 6:
                    if is_port:
                        packets[packet_index].payload.payload.sport = replace_sport
                        packets[packet_index].payload.payload.dport = replace_dport
                    packets[packet_index].payload.payload.seq = replace_src_seq + (packets[packet_index].payload.payload.seq - first_forward_packet.payload.payload.seq)
                    if not ("S" in packets[packet_index].payload.payload.flags and packets[packet_index].payload.payload.ack==0):
                        packets[packet_index].payload.payload.ack = replace_dst_seq + (packets[packet_index].payload.payload.ack - first_backward_packet.payload.payload.seq)
                    packets[packet_index].payload.payload.seq %= 2**32
                    packets[packet_index].payload.payload.ack %= 2**32
                elif packets[packet_index].payload.nh == 17:
                    if is_port:
                        packets[packet_index].payload.payload.sport = replace_sport
                        packets[packet_index].payload.payload.dport = replace_dport
        else: # backward
            if is_addr:
                packets[packet_index].payload.src = replace_dst
                packets[packet_index].payload.dst = replace_src
            if packets[packet_index].type == 0x0800:
                packets[packet_index].payload.id =  replace_dst_id + (packets[packet_index].payload.id - first_backward_packet.payload.id)
                packets[packet_index].payload.id %= 2**16
                #print("backward: ",replace_dst_id, packets[packet_index].payload.id)
                if packets[packet_index].payload.proto == 6:
                    if is_port:
                        packets[packet_index].payload.payload.sport = replace_dport
                        packets[packet_index].payload.payload.dport = replace_sport
                    packets[packet_index].payload.payload.seq = replace_dst_seq + (packets[packet_index].payload.payload.seq - first_backward_packet.payload.payload.seq)
                    if not ("S" in packets[packet_index].payload.payload.flags and packets[packet_index].payload.payload.ack==0):
                        packets[packet_index].payload.payload.ack = replace_src_seq + (packets[packet_index].payload.payload.ack - first_forward_packet.payload.payload.seq)
                    packets[packet_index].payload.payload.seq %= 2**32
                    packets[packet_index].payload.payload.ack %= 2**32
                elif packets[packet_index].payload.proto == 17:
                    if is_port:
                        packets[packet_index].payload.payload.sport = replace_dport
                        packets[packet_index].payload.payload.dport = replace_sport
            elif packets[packet_index].type == 0x86dd:
                packets[packet_index].payload.fl =  replace_dst_flowlabel + (packets[packet_index].payload.fl - first_backward_packet.payload.fl)
                packets[packet_index].payload.fl %= 2**20
                if packets[packet_index].payload.nh == 6:
                    if is_port:
                        packets[packet_index].payload.payload.sport = replace_sport
                        packets[packet_index].payload.payload.dport = replace_dport
                    packets[packet_index].payload.payload.seq = replace_src_seq + (packets[packet_index].payload.payload.seq - first_forward_packet.payload.payload.seq)
                    if not ("S" in packets[packet_index].payload.payload.flags and packets[packet_index].payload.payload.ack==0):
                        packets[packet_index].payload.payload.ack = replace_src_seq + (packets[packet_index].payload.payload.ack - first_forward_packet.payload.payload.seq)
                    packets[packet_index].payload.payload.seq %= 2**32
                    packets[packet_index].payload.payload.ack %= 2**32
                elif packets[packet_index].payload.nh == 17:
                    if is_port:
                        packets[packet_index].payload.payload.sport = replace_sport
                        packets[packet_index].payload.payload.dport = replace_dport
    return packets

def get_bursts(label_pcap, select_packet_len, corpora_path, start_index = 0, enhance_factor = 1, is_multi=False):
    if is_multi:
        pid = os.getpid()
    packets = scapy.rdpcap(label_pcap)
    No_ether = False
    if not hasattr(packets[0],'type'): #no ether header
        #print("No ethernet...")
        No_ether = True
        #start_index -= 28
        #return 0
    if (not No_ether and packets[0].type == 0x86dd) or (No_ether and packets[0].version == 6): #not handle ipv6
        return 0
    if len(packets)==0:
        return 0

    packet_direction = [] 
    feature_result = extract(label_pcap)
    for key in feature_result.keys():
        value = feature_result[key]
        packet_direction = [x // abs(x) for x in value.ip_lengths]


    if len(packet_direction) == len(packets):
        burst_extra_info = ''

        if No_ether:
            if packets[0].version == 4 and packets[0].proto == 6:
                burst_extra_info += '0'
            elif packets[0].version == 4 and packets[0].proto == 17:
                burst_extra_info += '1'
            else:
                burst_extra_info += '2'
        else:
            if packets[0].type == 0x0800 and packets[0].payload.proto == 6:
                burst_extra_info += '0'
            elif packets[0].type == 0x0800 and packets[0].payload.proto == 17:
                burst_extra_info += '1'
            # elif packets[0].type == 0x86dd:
            #     if packets[0].payload.nh == 6:
            #         burst_extra_info += '2'
            #     elif packets[0].payload.nh == 17:
            #         burst_extra_info += '3'
            else:
                burst_extra_info += '2'
        burst_extra_info += '\n'
        
        
        burst_txt = ''
        for en in range(enhance_factor):
            if en>0:
                packets = enhancement(packets)

            packetss = []
            packet_directionss = []
            new_packet_direction = []
            new_packets = scapy.PacketList()
            for packet_index in range(len(packets)):
                new_packets.append(packets[packet_index])
                new_packet_direction.append(packet_direction[packet_index])
                if (packet_index+1)%100==0:
                    packetss.append(new_packets)
                    packet_directionss.append(new_packet_direction)
                    new_packets = scapy.PacketList()
                    new_packet_direction = []
            if len(new_packets)>0:
                packetss.append(new_packets)
                packet_directionss.append(new_packet_direction)

            for pp in range(len(packetss)):
                packets = packetss[pp]
                packet_direction = packet_directionss[pp]
                burst_data_string = ''
                for packet_index in range(len(packets)):
                    packet_data = packets[packet_index].copy()
                    data = (binascii.hexlify(bytes(packet_data)))
                    
                    if No_ether: # add ether header
                        packet_string = data.decode()
                        if packet_direction[packet_index]==1:
                            packet_string = "c49a025996f8e46f13e2e3ae0800" + packet_string
                        else:
                            packet_string = "e46f13e2e3aec49a025996f80800" + packet_string
                        packet_string = packet_string[start_index:start_index+2*select_packet_len]
                    else:
                        packet_string = data.decode()[start_index:start_index+2*select_packet_len]
                    

                    if packet_index == 0:
                        packet_string = "||" + packet_string #a new flow
                        burst_data_string += packet_string
                    else:
                        if packet_direction[packet_index] != packet_direction[packet_index - 1]:
                            
                            length = len(burst_data_string)
                            for string_txt in cut(burst_data_string, int(length / 2)):
                                burst_txt += string_txt
                                #burst_txt += bigram_generation(string_txt, packet_len=len(string_txt))
                                burst_txt += '\n'
                            burst_txt += '\n'
                            
                            burst_data_string = ''
                        
                        burst_data_string += packet_string
                        if packet_index == len(packets) - 1:
                            
                            length = len(burst_data_string)
                            for string_txt in cut(burst_data_string, int(length / 2)):
                                burst_txt += string_txt
                                #burst_txt += bigram_generation(string_txt, packet_len=len(string_txt))
                                burst_txt += '\n'
                            burst_txt += '\n'
        if is_multi:
            with open(corpora_path+"{}_biburst.txt".format(pid),'a') as f:
                f.write(burst_txt)
        else:
            with open(corpora_path,'a') as f:
                f.write(burst_txt)

    return 0

def get_consecutive_packets(label_pcap, select_packet_len, corpora_path,start_index = 0):
    packets = scapy.rdpcap(label_pcap)

    if not hasattr(packets[0],'type'):
        print("No ethernet...")
        return 0
        
    packet_direction = []
    feature_result = extract(label_pcap)
    for key in feature_result.keys():
        value = feature_result[key]
        packet_direction = [x // abs(x) for x in value.ip_lengths]

    if len(packet_direction) == len(packets):
        burst_txt = ''
        burst_direction = ''
        for packet_index in range(len(packets)):
            packet_data = packets[packet_index].copy()
            data = (binascii.hexlify(bytes(packet_data)))
            
            packet_string = data.decode()[start_index:start_index+2*select_packet_len]
            
            if packet_index == 0:
                burst_txt += packet_string
                burst_txt += '\n'
            else:
                burst_txt += packet_string
                burst_txt += '\n'
                burst_txt += '\n'
                burst_txt += packet_string
                if packet_direction[packet_index] != packet_direction[packet_index - 1]:
                    burst_direction += '0'
                else:
                    burst_direction += '1'
        
        with open(corpora_path,'a') as f:
            f.write(burst_txt)
        with open(corpora_path[:-4]+"_extra.txt",'a') as f: 
            f.write(burst_direction)
    return 0

def merge(path):
    pid_set = set()
    for filename in os.listdir(path):
        pid_set.add(filename.split('_')[0])
    with open(path[:-1]+"_biburst.txt",'w') as fw1:
       #with open(path[:-1]+"_extra.txt",'w') as fw2:
            for key in pid_set:
                with open(path + key+"_biburst.txt",'r') as fr:
                    while True:
                        line = fr.readline()
                        if not line:
                            break
                        fw1.write(line)
                # with open(path + key+"_extra.txt",'r') as fr:
                #     while True:
                #         line = fr.readline()
                #         if not line:
                #             break
                #         fw2.write(line)
            
def pretrain_dataset_generation(pcapng_path,pcap_output_path,output_split_path,select_packet_len,corpora_path,start_index=0, enhance_factor = 1, is_multi=True):
    # pcapng_path: the path of pcapng files (if the traffic is the pacp type, pcapng_path = pcap_output_path)
    # pcap_output_path: the path of pcap files
    # output_split_path: the path of splited pcap files
    # start_index: the index of start byte (the number of byte * 2, i.e., If start from IP header, start_index = 28)
    # select_packet_len: the bytes of used
    # enhance_factor: enhance factor, enhance_factor = 1 represents do not enhance the pretrain data
    # is_multi: use multi process or not, the number of process is set at line: pool = mp.Pool(100)

    if not os.listdir(pcap_output_path):
        print("Begin to convert pcapng to pcap.")
        for _parent,_dirs,files in os.walk(pcapng_path):
            for file in files:
                if 'pcapng' in file:
                    #print(_parent + file)
                    convert_pcapng_2_pcap(_parent, file, pcap_output_path)
                else:
                    shutil.copy(_parent+"/"+file, pcap_output_path+file)
    
    if not os.path.exists(output_split_path + "splitcap"):
        print("Begin to split pcap as session flows.")
        for _p,_d,files in os.walk(pcap_output_path):
            for file in files:
                split_cap(output_split_path,pcap_output_path,file)

    print("Begin to generate burst dataset.")
    if is_multi:
        all_files = []
        for _p,_d,files in os.walk(output_split_path + "splitcap"):
            for file in files:
                all_files.append(_p+"/"+file)
        pbar = tqdm(total=len(all_files))
        pbar.set_description('get bursts')
        update = lambda *args: pbar.update()
        
        if not os.path.exists(corpora_path):
            os.makedirs(corpora_path)

        pool = mp.Pool(100)
        
        for file in all_files:
            pool.apply_async(get_bursts, (file, select_packet_len, corpora_path, start_index, enhance_factor, True), callback=update)
        pool.close()
        pool.join()
        print("start merge files...")
        merge(corpora_path)
        os.system(f'rm -r {corpora_path}')
    else:
        for _p,_d,files in os.walk(output_split_path + "splitcap"):
            for file in tqdm(files):
                get_bursts(_p+"/"+file, select_packet_len=select_packet_len,corpora_path=corpora_path,  start_index = start_index, enhance_factor=enhance_factor)

    return 0

def corpora_to_bigram(corpora_path,corpora_bigram_path):
    with open(corpora_bigram_path,'w') as fw:
        with open(corpora_path,'r') as fr:
            while True:
                line = fr.readline()
                if not line:
                    break
                if not line.strip():
                    fw.write(line)
                else:
                    newline = bigram_generation(line.strip(), token_len=len(line.strip()))
                    if newline[:2] == "||":
                        newline = "||"+newline[5:]
                    fw.write(newline+"\n")       

def corpora_to_gram(corpora_path,corpora_gram_path):
    with open(corpora_gram_path,'w') as fw:
        with open(corpora_path,'r') as fr:
            while True:
                line = fr.readline()
                if not line:
                    break
                if not line.strip():
                    fw.write(line)
                else:
                    if line[:2] == "||":
                        newline = gram_generation(line.strip()[2:])
                        newline = "||"+newline
                    else:
                        newline = gram_generation(line.strip())
                    fw.write(newline+"\n")         

def read_flows(path):
    print("process ",path)
    file1 = []
    with open(path,'r') as fr:
        flow = []
        while True:
            line = fr.readline()
            if not line:
                break
            if line[:2] == "||":
                if len(flow)>0:
                    file1.append(flow)
                flow = []
                flow.append(line)
            else:
                flow.append(line)
        if len(flow)>0:
            file1.append(flow)
    return file1

def merge_txts():
    corpora_path1 = "corpora1.txt"
    corpora_path2 = "corpora2.txt"
    corpora_path3 = "corpora3.txt"
    corpora_path = "corpora.txt"
    file1 = read_flows(corpora_path1)
    for flow in file1:
        if len(flow)>100000:
            print(len(flow))

    file2 = read_flows(corpora_path2)
    for flow in file2:
        if len(flow)>100000:
            print(len(flow))
    file3 = read_flows(corpora_path3)
    for flow in file3:
        if len(flow)>100000:
            print(len(flow))
    files = file1 + file2 + file3
    random.shuffle(files)
    return
