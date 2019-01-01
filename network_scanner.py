#! /usr/bin/env python

import scapy.all as scapy
import optparse

def getArg():
            parser= optparse.OptionParser()

            parser.add_option("-r","--range",dest="range",help="Provide Range of network mask")
            (options,arguments)=parser.parse_args()
            if not options.range:
                print("[-]Please provide range")
                exit()
            return options



def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    brodcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_brod= brodcast/arp_req

    ans_list= scapy.srp(arp_brod,timeout=1, verbose=False)[0]
    print("IP Address\t\tMac Address")
    print("----------------------------------------- ")
    for element in ans_list:
        print(element[1].psrc+"\t\t"+element[1].hwsrc)

    print("-----------------------------------------")


options=getArg()
scan(options.range)
