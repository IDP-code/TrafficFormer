import os
import random
import shutil
import binascii
import scapy.all as scapy
from functools import reduce
from flowcontainer.extractor import extract
from utils import *
import json,operator
from tqdm import tqdm
import pickle
import multiprocessing as mp
import numpy as np
from sklearn.model_selection import StratifiedShuffleSplit
import pandas as pd
from sklearn.model_selection import train_test_split
import string
#scapy.load_layer("tls")
from scapy.layers.tls.handshake import TLSClientHello,TLSServerHello
#from scapy.layers.tls.extensions import TLS_Ext_ServerName

def random_tcp_ts_option(packets):
    src_ts = None
    dst_ts = None
    random_src_ts = random_field(32)
    random_dst_ts = random_field(32)
    src_port = None
    for packet in packets:
        if packet.haslayer(scapy.TCP):
            tcp_options = [list(option) for option in packet['TCP'].options]
            for option in tcp_options:
                if option[0] == 'Timestamp':
                    if src_port==None:
                        src_port = packet['TCP'].sport
                        src_ts = option[1][0]
                        if option[1][1]!=0:
                            dst_ts = option[1][1]
                    if packet['TCP'].sport == src_port:
                        if option[1][1]!=0:
                            option[1] = (random_src_ts + option[1][0]-src_ts, random_dst_ts + option[1][1]-dst_ts)
                        else:
                            option[1] = (random_src_ts + option[1][0]-src_ts, 0)
                    else:
                        if dst_ts==None:
                            dst_ts = option[1][0]
                        if option[1][1]!=0:
                            option[1] = (random_dst_ts + option[1][0]-dst_ts, random_src_ts + option[1][1]-src_ts)
                        else:
                            option[1] = (random_dst_ts + option[1][0]-dst_ts, 0)

            packet['TCP'].options = [tuple(option) for option in tcp_options]
    return packets

def random_tls_sni():
    # We're using few bytes and won't get to the sni field
    # server name(sni) is a variable-length field, modifying it triggers a series of length modifications, ranging from tls extension length, tls length, IP length, and even packet ack.
    scapy.load_layer("tls")
    from scapy.layers.tls.handshake import TLSClientHello,TLSServerHello
    from scapy.layers.tls.extensions import TLS_Ext_ServerName
    packets = scapy.rdpcap("1.pcap")
    count = 0
    for packet in packets:
        # change server name
        print(count)
        count+=1
        if packet.haslayer(TLSClientHello):
            tls_client_hello = packet[TLSClientHello]
            tls_client_hello.show()
            print(packet['IP'].len,packet[TLS].len,tls_client_hello.msglen,tls_client_hello.extlen)
            add = 0
            if tls_client_hello.ext==None:
                continue
            for ext in tls_client_hello.ext:
                # Check for Server Name extension
                if isinstance(ext, TLS_Ext_ServerName):
                    for server_name in ext.servernames:
                        random_length = random.randint(10, 25) #random length
                        #random_length = server_name.namelen #keep length
                        print(random_length)
                        # ramdom server name
                        random_server_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random_length))
                        print(random_server_name)
                        server_name.servername = random_server_name.encode("UTF-8")
                        add += random_length - server_name.namelen
                        server_name.namelen = random_length
                        server_name.nametype = 0
                    
                    print("add: ", add)
                    ext.len += add
                    ext.servernameslen += add
                
            tls_client_hello.extlen +=add
            tls_client_hello.msglen +=add
            packet[TLS].len += add
            packet['IP'].len += add
        
        #change tls1.2 timestamps
        if packet.haslayer(TLSClientHello):
            packet[TLSClientHello].gmt_unix_time = random_field(32)
        if packet.haslayer(TLSServerHello):
            packet[TLSServerHello].gmt_unix_time = random_field(32)

    scapy.wrpcap("random_sni.pcap", packets)

def random_ip_port(packets:scapy.PacketList):
    if len(packets) > 0:
        if scapy.IP in packets[0]:
            client_ip = packets[0][scapy.IP].src
            server_ip = packets[0][scapy.IP].dst
            r_client_ip = random_ipv4()
            r_server_ip = random_ipv4()
        elif scapy.IPv6 in packets[0]:
            client_ip = packets[0][scapy.IPv6].src
            server_ip = packets[0][scapy.IPv6].dst
            r_client_ip = random_ipv6()
            r_server_ip = random_ipv6() 
            
        else:
            print("other L3 protocol")
        r_client_port = random_field(16)
        r_server_port = random_field(16)
    else:
        print("No packet in the pcap file")
        return -1

    for packet in packets:
        if scapy.IP in packet:
            is_client = packet[scapy.IP].src==client_ip
            packet[scapy.IP].src = r_client_ip if is_client else r_server_ip
            packet[scapy.IP].dst = r_server_ip if is_client else r_client_ip
            if scapy.TCP in packet:
                packet[scapy.TCP].sport = r_client_port if is_client else r_server_port
                packet[scapy.TCP].dport = r_server_port if is_client else r_client_port
            if scapy.UDP in packet:
                packet[scapy.UDP].sport = r_client_port if is_client else r_server_port
                packet[scapy.UDP].dport = r_server_port if is_client else r_client_port
        if scapy.IPv6 in packet:
            is_client = packet[scapy.IPv6].src==client_ip
            packet[scapy.IPv6].src = r_client_ip if is_client else r_server_ip
            packet[scapy.IPv6].dst = r_server_ip if is_client else r_client_ip
            if scapy.TCP in packet:
                packet[scapy.TCP].sport = r_client_port if is_client else r_server_port
                packet[scapy.TCP].dport = r_server_port if is_client else r_client_port
            if scapy.UDP in packet:
                packet[scapy.UDP].sport = r_client_port if is_client else r_server_port
                packet[scapy.UDP].dport = r_server_port if is_client else r_client_port
    
    return packets

def random_tls_randomtime(packets:scapy.PacketList):
    for packet in packets:
        if packet.haslayer(TLSClientHello):
            packet[TLSClientHello].gmt_unix_time = random_field(32)
        if packet.haslayer(TLSServerHello):
            packet[TLSServerHello].gmt_unix_time = random_field(32)
    return packets

def get_feature_flow(label_pcap, select_packet_len, packets_num, start_index=76, add_sep=True):
    
    feature_data = []
    packets = scapy.rdpcap(label_pcap)
    packet_count = 0  
    flow_data_string = '' 

    No_ether = False
    if not hasattr(packets[0],'type'): #no ether header
        No_ether = True
    if (not No_ether and packets[0].type == 0x86dd) or (No_ether and packets[0].version == 6): #do not handle IPV6
        return -1
    
    feature_result = extract(label_pcap, filter='tcp', extension=['tls.record.content_type', 'tls.record.opaque_type', 'tls.handshake.type'])

    if len(feature_result) == 0:
        feature_result = extract(label_pcap, filter='udp')
        if len(feature_result) == 0:
            return -1
        extract_keys = list(feature_result.keys())[0]
        if len(feature_result[label_pcap, extract_keys[1], extract_keys[2]].ip_lengths) < 3:
            print("preprocess udp flow %s but this flow has less than 3 packets." % label_pcap)
            return -1
    elif len(packets) < 3:
        print("preprocess tcp flow %s but this flow has less than 3 packets." % label_pcap)
        return -1
    try:
        if len(feature_result[label_pcap, 'tcp', '0'].ip_lengths) < 3:
            print("1: preprocess flow %s but this flow has less than 3 packets." % label_pcap)
            return -1
    except Exception as e:
        #print("*** this flow begins from 1 or other numbers than 0.")
        for key in feature_result.keys():
            if len(feature_result[key].ip_lengths) < 3:
                print("2: preprocess flow %s but this flow has less than 3 packets." % label_pcap)
                return -1
    
    if feature_result == {}:
        return -1

    packet_length = []
    packet_time = []
    packet_direction = []
    packet_message_type = []
    

    feature_result_lens = len(feature_result.keys())
    for key in feature_result.keys():
        value = feature_result[key]
        packet_length.append(value.ip_lengths)
        packet_time.append(value.ip_timestamps)

        if len(packet_length) < feature_result_lens:
            continue
        elif len(packet_length) == 1:
            pass
        else:
            packet_length = [sum(packet_length, [])]
            packet_time = [sum(packet_time, [])]

        extension_dict = {}
        
        for len_index in range(len(packet_length)):
            extension_list = [0]*(len(packet_length[len_index]))

        extensions = value.extension
        
        if 'tls.record.content_type' in extensions.keys():
            for record_content in extensions['tls.record.content_type']:
                packet_index = record_content[1]
                ms_type = []
                
                if len(record_content[0]) > 2:
                    ms_type.extend(record_content[0].split(','))
                else:
                    ms_type.append(record_content[0])
                
                extension_dict[packet_index] = ms_type
            
            if 'tls.handshake.type' in extensions.keys():
                for tls_handshake in extensions['tls.handshake.type']:
                    packet_index = tls_handshake[1]
                    if packet_index not in extension_dict.keys():
                        continue
                    ms_type = []
                    if len(tls_handshake[0]) > 2:
                        ms_type.extend(tls_handshake[0].split(','))
                    else:
                        ms_type.append(tls_handshake[0])
                    source_length = len(extension_dict[packet_index])
                    for record_index in range(source_length):
                        if extension_dict[packet_index][record_index] == '22':
                            for handshake_type_index in range(len(ms_type)):
                                extension_dict[packet_index][record_index] = '22:' + ms_type[handshake_type_index]
                                if handshake_type_index > 0:
                                    extension_dict[packet_index].insert(handshake_type_index,
                                                                        ('22:' + ms_type[handshake_type_index]))
                            break
        if 'tls.record.opaque_type' in extensions.keys():
            for record_opaque in extensions['tls.record.opaque_type']:
                packet_index = record_opaque[1]
                ms_type = []
                if len(record_opaque[0]) > 2:
                    ms_type.extend(record_opaque[0].split(","))
                else:
                    ms_type.append(record_opaque[0])
                if packet_index not in extension_dict.keys():
                    extension_dict[packet_index] = ms_type
                else:
                    extension_dict[packet_index].extend(ms_type)
        
        # extension_dict is {0: ['22:2', '20'], 16: ['20', '23'], 7: ['23'],...}

        is_source = 0
        if is_source: #one method record tls type
            # {0: '22:2,20', 16: '20,23', 7: '23',...}
            extension_string_dict = {}
            for key in extension_dict.keys():
                temp_string = ''
                for status in extension_dict[key]:
                    temp_string += status+','
                temp_string = temp_string[:-1]
                extension_string_dict[key] = temp_string
            packet_message_type.append(extension_string_dict)
        else: #Another method record tls type
            # [64,...,23,...,43] [22*2+20,...,23,...,20+23]
            for key in extension_dict.keys():
                if len(set(extension_dict[key])) == 1 and len(extension_dict[key]) > 1: 
                    try:
                        extension_list[key] += len(extension_dict[key])
                    except Exception as e:
                        print(key)
                else:
                    for status in extension_dict[key]:
                        if ':' in status:
                            extension_list[key] += reduce(operator.mul, [int(x) for x in status.split(':')], 1)
                        else:
                            if key <= len(packet_length[0]): 
                                extension_list[key] += int(status)
                            else:
                                with open("error_while_writin_record","a") as f:
                                    f.write(label_pcap + '\n')
                                continue
            packet_message_type.append(extension_list)

    for length in packet_length[0]:
        if length > 0:
            packet_direction.append(1)
        else:
            packet_direction.append(-1)


    packet_index = 0

    packets = random_ip_port(packets)
    packets = random_tcp_ts_option(packets)
    packets = random_tls_randomtime(packets)

    for packet in packets:
        packet_data = packet.copy()
        data = (binascii.hexlify(bytes(packet_data)))
        if No_ether:
            packet_string = data.decode()
            if packet_direction[packet_index]==1:
                packet_string = "c49a025996f8e46f13e2e3ae0800" + packet_string
            else:
                packet_string = "e46f13e2e3aec49a025996f80800" + packet_string
            packet_string = packet_string[start_index:start_index+2*select_packet_len]
        else:
            packet_string = data.decode()[start_index:start_index+2*select_packet_len]
        
        if add_sep:
            flow_data_string += "[SEP] "
        flow_data_string += bigram_generation(packet_string.strip(), token_len=len(packet_string.strip()), flag = True)
        #flow_data_string += gram_generation(packet_string.strip())
        packet_count += 1
        if packet_count == packets_num:
            break

    feature_data.append(flow_data_string)
    feature_data.append(packet_length[0])
    feature_data.append(packet_time[0])
    feature_data.append(packet_direction)
    feature_data.append(packet_message_type[0])

    return feature_data

def process_one_label(session_pcap_path,key,payload_length,payload_packet,samples,label_id,start_index=76):
    result = {
            "samples": 0,
            "datagram": {},
            "length": {},
            "time": {},
            "direction": {},
            "message_type": {}
        }

    target_all_files = [x[0] + "/" + y for x in [(p, f) for p, d, f in os.walk(session_pcap_path[key])] for y in x[1]]
    # for f in target_all_files:
    #     file_size = float(size_format(os.path.getsize(pcap_split_path+"splitcap" + "/" + dir + "/" + f)))
    #     if file_size>
    label_count = label_id[key]
    if len(target_all_files)>samples[label_count]:
        random.seed(10)
        r_files = random.sample(target_all_files, samples[label_count])
    else:
        r_files = target_all_files
    for r_f in  r_files:
        try:
            feature_data = get_feature_flow(r_f, select_packet_len=payload_length, packets_num=payload_packet,start_index=start_index)
        except:
            feature_data = -1

        if feature_data == -1:
            continue
        
        result["samples"] += 1
        if len(result["datagram"].keys()) > 0:
            result["datagram"][str(result["samples"])] = feature_data[0]
            result["length"][str(result["samples"])] = \
                feature_data[1]
            result["time"][str(result["samples"])] = \
                feature_data[2]
            result["direction"][str(result["samples"])] = \
                feature_data[3]
            result["message_type"][str(result["samples"])] = \
                feature_data[4]
        else:
            result["datagram"]["1"] = feature_data[0]
            result["length"]["1"] = feature_data[1]
            result["time"]["1"] = feature_data[2]
            result["direction"]["1"] = feature_data[3]
            result["message_type"]["1"] = feature_data[4]

    with open("/mnt/data/zgm/ET-BERT/fine-tuning/temp/"+key,'wb') as f:
        pickle.dump(result,f)

def generation_multiP(pcap_path, samples, dataset_save_path, payload_length = 64, payload_packet = 5, start_index=76):
    # pcap_path: the path of splited pcap. In the pacp path, each dir is one class. In each dir, each pcap is one flow.
    # samples: samples * _category, samples is the maximum samples of each class, _category is the number of class.
    # dataset_save_path: generated dataset path
    # payload_length: the used bytes of data
    # payload_packet: the used packets 
    # start_index: the index of start byte (the number of byte * 2, i.e., If start from IP header, start_index = 28)
    dataset = {}
    label_name_list = []
    session_pcap_path  = {}

    for parent, dirs, files in os.walk(pcap_path):
        if label_name_list == []:
            label_name_list.extend(dirs)

        for dir in label_name_list:
            session_pcap_path[dir] = pcap_path + dir
        break
    print("label number: ",len(label_name_list))

    label_id = {}
    for index in range(len(label_name_list)):
        label_id[label_name_list[index]] = index
    #print(label_id['Benign'])
    for key in label_id.keys():
        print(key,label_id[key])

    print("\nBegin to generate features.")
    pbar = tqdm(total=len(session_pcap_path.keys()))
    pbar.set_description('generate features')
    update = lambda *args: pbar.update()

    pool = mp.Pool(min(120,len(label_name_list)))
    for key in session_pcap_path.keys():
        #process_one_label(session_pcap_path,"FTP.pcap",payload_length,payload_packet,samples,label_id,start_index)
        pool.apply_async(process_one_label,(session_pcap_path,key,payload_length,payload_packet,samples,label_id,start_index), callback=update)
    pool.close()
    pool.join()

    for key in os.listdir("./temp/"):
        with open("./temp/"+key,'rb') as f:
            result = pickle.load(f)
        dataset[label_id[key]] = result
        os.system(f'rm -r {"./temp/"+key}')

    all_data_number = 0
    for index in range(len(label_name_list)):
        #print("%s\t%s\t%d"%(label_id[label_name_list[index]], label_name_list[index], dataset[label_id[label_name_list[index]]]["samples"]))
        all_data_number += dataset[label_id[label_name_list[index]]]["samples"]
    print("all\t%d"%(all_data_number))

    with open(dataset_save_path + "/dataset.json", "w") as f:
        json.dump(dataset,fp=f,ensure_ascii=False,indent=4)

def convert_splitcap(pcapng_path, pcap_path,pcap_split_path,is_pcap_label=False):
    # pcapng_path: the path of pcapng files (if the traffic is the pacp type, pcapng_path = pcap_path)
    # pcap_path: the path of pcap files
    # pcap_split_path: the path of splited pcap files
    # pcapng to pcap
    if not os.listdir(pcap_path):
        for parent, dirs, files in os.walk(pcapng_path):
            for file in files:
                cmd = "editcap -F pcap %s %s"
                command = cmd%(parent+ "/" + file, pcap_path+ "/" + file)
                os.system(command)
    # split pcap
    label_name_list = []
    for parent, dirs, files in os.walk(pcap_path):
        if len(dirs)==0:
            for file in files:
                os.system(f"mkdir {pcap_path + file[:-5]}")
                os.system(f"mv {pcap_path + file} {pcap_path + file[:-5]}")
                label_name_list.append(file.split(".")[-2])
        else:
            label_name_list.extend(dirs)
        break
    print(len(label_name_list))
    for dir in label_name_list:
        for p,dd,ff in os.walk(parent + "/" + dir):
            for file in ff:
                if is_pcap_label:
                    output_path = split_cap(pcap_split_path, p + "/", file, pcap_label=dir)
                else:
                    output_path = split_cap(pcap_split_path, p + "/", file)
    # remove small pcap and split again big pcap
    for p,dd,ff in os.walk(pcap_split_path+"splitcap"):
        for dir in dd:
            for _,_,ff in os.walk(pcap_split_path+"splitcap" + "/" + dir):
                for f in ff:
                    file_size = float(size_format(os.path.getsize(pcap_split_path+"splitcap" + "/" + dir + "/" + f)))
                    # 2KB
                    if file_size < 2: #remove small pcap
                        os.remove(pcap_split_path+"splitcap" + "/" + dir + "/" + f)
                        #print("remove sample: %s for its size is less than 2 KB." % (pcap_split_path+"splitcap" + "/" + dir + "/" + f))
                    if file_size > 10240: #10MB  split again big pcap
                        print("bigger than 10MB")
                        cmd = "editcap -i 300 {} {}".format(pcap_split_path+"splitcap" + "/" + dir + "/" + f, pcap_split_path+"splitcap" + "/" + dir + "/" + f)
                        os.system(cmd)
                        os.system("rm {}".format(pcap_split_path+"splitcap" + "/" + dir + "/" + f))
                break
        break
    # remove class that has less flow
    all_flows = []
    for p,dd,ff in os.walk(pcap_split_path+"splitcap"):
        for dir in dd:
            for _,_,ff in os.walk(pcap_split_path+"splitcap" + "/" + dir):
                print(dir,len(ff))
                if len(ff)<10:
                    shutil.rmtree(pcap_split_path+"splitcap" + "/" + dir)
                    print("remove class: %s for its flow size is less than 10." % (pcap_split_path+"splitcap" + "/" + dir))
                else:
                    all_flows.append(len(ff))
        break
    print("all flows: ",sum(all_flows), len(all_flows))

def dataset_extract(dataset_save_path, features):
    
    print("read dataset from json file.")
    with open(dataset_save_path + "/dataset.json","r") as f:
        dataset = json.load(f)
    
    dataset_statistic = [0] * _category

    data_all = []
    for app_label in dataset.keys():
        for index_sample in range(len(dataset[app_label]["length"])):
            x = []
            for feature in features:
                x.append(dataset[app_label][feature][str(index_sample+1)])
            x.append(int(app_label))
            dataset_statistic[int(app_label)]+=1
            data_all.append(x)
    data = pd.DataFrame(data_all,columns=features+['label'])


    print("category flow")
    for index in range(len(dataset_statistic)):
        print("%s\t%d" % (index, dataset_statistic[index]))
    print("all\t%d" % (sum(dataset_statistic)))
     
	# split train set and test set
    data_train, data_test = train_test_split(data, test_size=0.2, random_state=41,stratify=data["label"])
    # split validate set and test set
    data_val, data_test = train_test_split(data_test, test_size=0.5, random_state=42,stratify=data_test["label"])

    print("label number of train: {}, val: {}, test: {}.".format(len(data_train['label'].value_counts()), len(data_val['label'].value_counts()),len(data_test['label'].value_counts()) ))

    data_train = data_train.reset_index(drop=True)
    data_val = data_val.reset_index(drop=True)
    data_test = data_test.reset_index(drop=True)

    if not os.path.exists(dataset_save_path+"dataset/"):
        os.mkdir(dataset_save_path+"dataset/")

    #save features to .pkl
    # with open(os.path.join(dataset_save_path + "dataset/", 'train.pkl'),"wb") as f:
    #     pickle.dump(data_train,f)
    # with open(os.path.join(dataset_save_path + "dataset/", 'test.pkl'),"wb") as f:
    #     pickle.dump(data_test,f)
    # with open(os.path.join(dataset_save_path + "dataset/", 'valid.pkl'),"wb") as f:
    #     pickle.dump(data_val,f)

    # save bytes to tsv
    write_dataset_tsv(data_train['datagram'], data_train['label'], dataset_save_path+"dataset/", "train")
    write_dataset_tsv(data_test['datagram'], data_test['label'], dataset_save_path+"dataset/", "test")
    write_dataset_tsv(data_val['datagram'], data_val['label'], dataset_save_path+"dataset/", "valid")
    print("finish generating pre-train's datagram dataset.\nPlease check in %s" % dataset_save_path+"dataset/")

def enhance_based_tsv(path,filename,new_file_prefix,enhance_factor=1):
    # path: the tsv path
    # filenmae: the name of tsv path
    # new_file_prefix: the prefix of enhanced tsv
    # enhance_factor: augmentation factor
    dataset  = []
    columns = {}
    with open(path+filename, mode="r", encoding="utf-8") as f:
        for line_id, line in enumerate(f):
            if line_id == 0:
                for i, column_name in enumerate(line.strip().split("\t")):
                    columns[column_name] = i
                continue
            line = line[:-1].split("\t")
            tgt = int(line[columns["label"]])
            text_a = line[columns["text_a"]]
            text_list = text_a.split("[SEP]")[1:]
            for _ in range(enhance_factor):
                # IPID:4, src:12, dst: 16, sport:20, dport:22, seq:24, ack:28
                IP,proto,first_forward_datagrams,first_backward_datagrams = None, None, None, None
                datagramss = []
                for i in range(len(text_list)):
                    pac = text_list[i]
                    datagrams = pac.split(" ")[1:-1]
                    datagramss.append(datagrams)
                    if i==0:
                        if datagrams[0][0]=="4": 
                            IP = 4
                            if datagrams[9][:2]=="06": proto = 6
                            elif datagrams[9][:2]=="11": proto = 17
                        elif datagrams[0][0]=="6":
                            IP = 6
                            if datagrams[6][:2]=="06": proto = 6
                            elif datagrams[6][:2]=="11": proto = 17
                        src = datagrams[12:16]
                        first_forward_datagrams = datagrams
                    if datagrams[12:16]!=src and first_backward_datagrams is None:
                        first_backward_datagrams = datagrams
                
                if IP==None or proto==None:
                    print(line)
                    return

                if IP==4:
                    rsrc = random_field(32)
                    rdst = random_field(32)
                    rsrcid = random_field(16)
                    rdstid = random_field(16)
                elif IP==6:
                    print("IPV6 is waiting to process")
                    continue
                if proto==6:
                    rsrcp = random_field(16)
                    rdstp = random_field(16)
                    rsrcseq = random_field(32)
                    rdstseq = random_field(32)
                elif proto==17:
                    rsrcp = random_field(16)
                    rdstp = random_field(16)
                
                forward_4tstr = hex(rsrc)[2:].zfill(8) + hex(rdst)[2:].zfill(8) + hex(rsrcp)[2:].zfill(4) + hex(rdstp)[2:].zfill(4)
                backward_4tstr = hex(rdst)[2:].zfill(8) + hex(rsrc)[2:].zfill(8) + hex(rdstp)[2:].zfill(4) + hex(rsrcp)[2:].zfill(4)
                srcipid = int(first_forward_datagrams[4], 16)
                if first_backward_datagrams is not None:
                    dstipid = int(first_backward_datagrams[4], 16)
                srcseq = int(first_forward_datagrams[24]+first_forward_datagrams[26], 16)
                srcack = int(first_forward_datagrams[28]+first_forward_datagrams[30], 16)
                if first_backward_datagrams is not None:
                    dstseq = int(first_backward_datagrams[24]+first_backward_datagrams[26], 16)
                elif srcack!=0:
                    dstseq = srcack
                else:
                    print("cant process dstseq...")
                #print(hex(srcseq),hex(dstseq),hex(rsrcseq),hex(rdstseq))
                
                #print(forward_4tstr, backward_4tstr)   
                for i in range(len(datagramss)):
                    # print("------")
                    # print(datagramss[i])
                    if datagramss[i][12:16]==src: #forward
                        datagramss[i][11] = datagramss[i][11][:2] + forward_4tstr[:2]
                        cc = 12
                        for elm in bigram_generation(forward_4tstr,token_len=len(forward_4tstr)/2).split(" ")[:-1]:
                            datagramss[i][cc] = elm
                            cc += 1
                        datagramss[i][cc] = forward_4tstr[-2:] + datagramss[i][cc][2:4]
                        # handle IPID
                        if IP==4:
                            if srcipid != 0:
                                temp = hex((int(datagramss[i][4],16) - srcipid + rsrcid)%(2**16))[2:].zfill(4)
                                datagramss[i][4] = temp
                                datagramss[i][3] = datagramss[i][3][:2] + temp[:2]
                                datagramss[i][5] = temp[2:] + datagramss[i][5][2:]
                        # handle seq
                        if proto==6:
                            tempsrcseq = hex((rsrcseq + int(datagramss[i][24]+datagramss[i][26], 16) - srcseq)%(2**32))[2:].zfill(8)
                            datagramss[i][23] = datagramss[i][23][:2] + tempsrcseq[:2]
                            cc = 24
                            for elm in bigram_generation(tempsrcseq,len(tempsrcseq)/2).split(" ")[:-1]:
                                datagramss[i][cc] = elm
                                cc += 1
                            datagramss[i][cc] = tempsrcseq[-2:] + datagramss[i][cc][2:4]
                            # handle ack
                            if int(datagramss[i][28]+datagramss[i][30], 16)!=0 and dstseq:
                                tempsrcack = hex((rdstseq + int(datagramss[i][28]+datagramss[i][30], 16) - dstseq)%(2**32))[2:].zfill(8)
                                datagramss[i][27] = datagramss[i][27][:2] + tempsrcack[:2]
                                cc = 28
                                for elm in bigram_generation(tempsrcack,len(tempsrcack)/2).split(" ")[:-1]:
                                    datagramss[i][cc] = elm
                                    cc += 1
                                datagramss[i][cc] = tempsrcack[-2:] + datagramss[i][cc][2:4]
                        
                    else:
                        datagramss[i][11] = datagramss[i][11][:2] + backward_4tstr[:2]
                        cc = 12
                        for elm in bigram_generation(backward_4tstr,token_len=len(backward_4tstr)/2).split(" ")[:-1]:
                            datagramss[i][cc] = elm
                            cc += 1
                        datagramss[i][cc] = backward_4tstr[-2:] + datagramss[i][cc][2:4]
                        # handle IPID
                        if IP==4:
                            if dstipid != 0:
                                temp = hex((int(datagramss[i][4],16) - dstipid + rdstid)%(2**16))[2:].zfill(4)
                                datagramss[i][4] = temp
                                datagramss[i][3] = datagramss[i][3][:2] + temp[:2]
                                datagramss[i][5] = temp[2:] + datagramss[i][5][2:]
                        # handle seq
                        if proto==6:
                            if dstseq:
                                tempdstseq = hex((rdstseq + int(datagramss[i][24]+datagramss[i][26], 16) - dstseq)%(2**32))[2:].zfill(8)
                                datagramss[i][23] = datagramss[i][23][:2] + tempdstseq[:2]
                                cc = 24
                                for elm in bigram_generation(tempdstseq,len(tempdstseq)/2).split(" ")[:-1]:
                                    datagramss[i][cc] = elm
                                    cc += 1
                                datagramss[i][cc] = tempdstseq[-2:] + datagramss[i][cc][2:4]
                            # handle ack
                            if int(datagramss[i][28]+datagramss[i][30], 16)!=0:
                                tempdstack = hex((rsrcseq + int(datagramss[i][28]+datagramss[i][30], 16) - srcseq)%(2**32))[2:].zfill(8)
                                datagramss[i][27] = datagramss[i][27][:2] + tempdstack[:2]
                                cc = 28
                                for elm in bigram_generation(tempdstack,len(tempdstack)/2).split(" ")[:-1]:
                                    datagramss[i][cc] = elm
                                    cc += 1
                                datagramss[i][cc] = tempdstack[-2:] + datagramss[i][cc][2:4]
                    #print(datagramss[i])
                
                newtext_a = ''
                for i in range(len(datagramss)):
                    if newtext_a!='': #2024.4.23 add
                        newtext_a += ' '
                    newtext_a += '[SEP]'
                    for j in range(len(datagramss[i])):
                        if newtext_a!='':
                            newtext_a += ' '
                        newtext_a += datagramss[i][j]
                        
                dataset.append([newtext_a,tgt])

    dataset = pd.DataFrame(dataset,columns=['datagram','label'])
    dataset = dataset.sample(frac = 1)
    # print(dataset.head())
    write_dataset_tsv(dataset['datagram'], dataset['label'], path, new_file_prefix)
