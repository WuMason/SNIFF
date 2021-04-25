# -*- coding=utf-8 -*-
import os
import re
import scapy
from scapy.all import *
from scapy.utils import PcapReader
from time import sleep

def zigbee_modle():
    print "input Ctrl + C to close"
    os.system('sudo whsniff -c 11 > tmp.pcap')
    os.system('pkill airodump-ng')
    #packets=rdpcap("./broad_all.pcap")
    #packets=rdpcap("./broad_user.pcap")
    #packets=rdpcap("./broad_mcu.pcap")
    #packets=rdpcap("./user_three.pcap")
    #packets=rdpcap("./user_mcu.pcap")
    #packets=rdpcap("./group.pcap")
    #packets=rdpcap("./group_23.pcap")
    #packets=rdpcap("./group_mcu.pcap")
    #packets=rdpcap("./broad_three.pcap")
    #packets=rdpcap("./xietiao_all.pcap")
    #packets=rdpcap("./luyou_all.pcap")
    #packets=rdpcap("./luyou_broad.pcap")
    #packets=rdpcap("./luyou_group.pcap")
    #packets=rdpcap("./luyou_user.pcap")
    packets=rdpcap("./tmp.pcap")
    packets_len = len(packets)
    print packets_len
    zigbee_mac = [0] * packets_len
    check_msg = [0] * packets_len
    counter = 1

    for j in range(packets_len):
        packet = packets[j]
        #check modle
        check_packet_ipv6 = packet.haslayer('IPv6')
        #group or mac address
        if check_packet_ipv6:
            pase_type = packet[IPv6].dst
            pase_type_len = len(pase_type)
            pase_type_list = [k.start() for k in re.finditer(":",pase_type)]
            pase_type_list_len = len(pase_type_list)
            #print pase_type
            #print pase_type_list
            new_pase_type = pase_type[pase_type_list[pase_type_list_len-1]+1:pase_type_len]
            #print new_pase_type
            
            playload = packet[IPv6].src
            playload_len = len(playload)
            #print playload
            playload_list = [k.start() for k in re.finditer(":",playload)]
            playload_list_len = len(playload_list)
            #print playload_list
            
            if new_pase_type == "ffff" or new_pase_type == "0":     
                #print j,"aaaaaaaa"
                message = playload[playload_list[2]+1:playload_list[3]] + playload[playload_list[3]+1:playload_list[4]].zfill(4) + playload[playload_list[4]+1:playload_list[5]].zfill(4) + playload[playload_list[5]+1:playload_list[6]].zfill(4) + playload[playload_list[6]+1:playload_list_len].zfill(2)
                pattern = re.compile('.{2}')
                zigbee_mac[j] = ':'.join(pattern.findall(message))  
            else:
                #print j,"bbbbb"
                message = playload[playload_list[2]+1:playload_list[3]].zfill(4) + playload[playload_list[3]+1:playload_list[4]].zfill(4) + playload[playload_list[4]+1:playload_list[5]].zfill(4) + playload[playload_list[5]+1:playload_list[6]].zfill(4)
                pattern = re.compile('.{2}')
                zigbee_mac[j] = ':'.join(pattern.findall(message)) 
        #broad
        else:   
            check_packet_raw = packet.haslayer('Raw')
            if check_packet_raw:
                check_data = packet.haslayer('802.15.4 Data')
                if check_data:
                    playload = packet[Raw].load
                    playload_len = len(playload)
                    message  = [0] * playload_len

                    for i in range(playload_len):
                        message[i] = playload[i].encode('hex')
                    #print message
                    if message[7] == "00" and message[8] == "00":
                        #print j,"cccccccc"
                        zigbee_mac[j] = message[9]+":"+message[10]+":"+message[11]+":"+message[12]+":"+message[13]+":"+message[14]+":"+message[15]+":"+message[16]   
                    else:
                        zigbee_mac[j] = message[4]+":"+message[5]+":"+message[6]+":"+message[7]+":"+message[8]+":"+message[9]+":"+message[10]+":"+message[11]
                        #print j,"dddddd"

    check_zigbee_mac = list(set(zigbee_mac))
    check_zigbee_mac.sort(key=zigbee_mac.index)
    check_zigbee_mac_len = len(check_zigbee_mac)
    print "Zigbee mac adress counter=",check_zigbee_mac_len
    print "Zigbee Mac address:"
    for g in range(check_zigbee_mac_len):
        print counter,check_zigbee_mac[g]
        counter += 1
        
        
def wifi_modle():
    #check env
    os.system('sudo airmon-ng start wlan0')
    os.system('sudo airodump-ng -w ap_terminal wlan0mon')
    os.system('pkill airodump-ng')

    print "Select a wireless interface for target searching..."
    i=0
    k=0
    AP_MAC  = [0] * 100
    try:
        with open("ap_terminal-01.csv") as lines:
            for line in lines:
                i=i+1
                if i>2:
                    index_list = [j.start() for j in re.finditer(',', line)]
                    #print "list=",index_list
                    lenth = len(index_list)
                    if lenth == 14:
                        AP_MAC[k]  = "bssid="+line[0:17]+ "   chanel="+ line[index_list[2]+1:index_list[3]]+ "   essid="+ line[index_list[12]+1:index_list[13]]
                        print k,AP_MAC[k]
                        k=k+1
    except:
        print "Unable to determine interface driver or Unable to use interface! "
        os._exit(0)
    os.system("sudo rm ap_terminal-*")
    choose_wifi = input("Please select the number you want to view:")
    view_wifi_terminal(AP_MAC[choose_wifi])


def view_wifi_terminal(self):
    os.system("clear")
    search_bssid = re.search(r'bssid=(.*?)   chanel=', self)
    search_chanel = re.search(r'chanel=(.*?)   essid=', self)
    bssid = format(search_bssid.group(1))
    chanel = format(search_chanel.group(1))

    sys_str = "sudo airodump-ng -c " + chanel + " -w wifi_terminal --bssid " + bssid + " wlan0mon"
    output = os.popen(sys_str)
    sleep(6)
    os.system('pkill airodump-ng')
    print "AP Mac address:",bssid
    print "Terminal Mac address:"
    i=0
    with open("wifi_terminal-01.csv") as lines:
        for line in lines:
            i=i+1
            if i>5:
                Station_MAC = line[0:17]
                print Station_MAC
    os.system("sudo rm wifi_terminal-*")
    os.system('sudo airmon-ng stop wlan0mon')

def ble_modle():
    os.system("clear")
    print "Please waitting ......"
    os.system('pkill ubertooth-btle')
    os.system("sudo ubertooth-btle -n -c ble_data.pcap")
    os.system('pkill ubertooth-btle')    
    packets = rdpcap("./ble_data.pcap")
    packets_len = len(packets)
    ble_mac = [0] * packets_len
    print "packets_len=",packets_len

    for j in range(packets_len):
        packet = packets[j]
        playload = packet[Raw].load
        playload_len = len(playload)

        if playload_len >12:
            message  = [0] * playload_len

            for i in range(playload_len):
                message[i] = playload[i].encode('hex')

            ble_mac[j] = message[11]+":"+message[10]+":"+message[9]+":"+message[8]+":"+message[7]+":"+message[6]

    check_ble_mac = list(set(ble_mac))
    check_ble_mac.sort(key=ble_mac.index)
    check_ble_mac_len = len(check_ble_mac)

    print "Ble mac adress counter=",check_ble_mac_len
    print "Bluetooth Mac address:"
    for g in range(check_ble_mac_len):
        print g,check_ble_mac[g]        
    os.system("sudo rm ble_data*")

if __name__ == '__main__':
    os.system("clear")
    print('                                                  .__  _____  _____  ')
    print('                                      ______ ____ |__|/ ____\/ ____\ ')
    print('                                     /  ___//    \|  \   __\\   __\  ')
    print('                                     \___ \|   |  \  ||  |   |  |    ')
    print('                                    /____  >___|  /__||__|   |__|    ')
    print('                                         \/     \/                   ')
    print(" ")
    print("[*]Working!Please input the number!")

    print("[0] WiFi")
    print("[1] Bluetooth")
    print("[2] Zigbee")
    print("[3] NB-IoT(watting...)")
    print("[4] LoRa(watting...)")
    modle = input("Number:")
    modle = int(modle)
    if modle == 0:
        wifi_modle()
    if modle == 1:
        ble_modle()  
    if modle == 2:
        zigbee_modle()
    else:
        print("Error number!")




