#!/usr/bin/env python2

from os import geteuid, devnull
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
from sys import exit
import argparse
import signal
from base64 import b64decode
from urllib import unquote
from subprocess import Popen, PIPE
from IPython import embed

DN = open(devnull, 'w')
pkt_frag_loads = {}

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-i", "--interface", help="Choose an interface")
   parser.add_argument("-p", "--pcap", help="Parse info from a pcap file; -p <pcapfilename>")
   return parser.parse_args()

def iface_finder():
    try:
        ipr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
        for line in ipr.communicate()[0].splitlines():
            if 'default' in line:
                l = line.split()
                iface = l[4]
                return iface
    except Exception:
        exit('[-] Could not find an internet active interface; please specify one with -i <interface>')

def frag_remover(ack, src_ip_port, load):
    '''
    Remove concatenated fragmented packet loads every 3 minutes
    '''
    global pkt_frag_loads

    for dict_ip_port in pkt_frag_loads:
        # Remove old fragmented loads
        if len(pkt_frag_loads[dict_ip_port]) > 0:
            for ack in pkt_frag_loads[dict_ip_port]:
                frag_time = pkt_frag_loads[dict_ip_port][ack][1]
                # if the frag load is from longer than 3m ago remove it
                if time.time() - frag_time > 180:
                    pkt_frag_loads[dict_ip_port].pop(ack)

def frag_joiner(ack, src_ip_port, load):
    '''
    Keep a store of previous fragments in pkt_frag_loads
    also store the time of the last incoming frag
    so we can remove old loads
    '''
    for dict_ip_port in pkt_frag_loads:
        if src_ip_port == dict_ip_port:
            if ack in pkt_frag_loads[src_ip_port]:
                # Make pkt_frag_loads[src_ip_port][ack] = (full load, time)
                old_load = pkt_frag_loads[src_ip_port][ack][0]
                concat_load = old_load + load
                print 'info: ', ack, repr(load[-50:])
                #if not len(concat_load) > 100000:
                return {ack:(old_load+load, time.time())}

    return {ack:(load, time.time())}

def pkt_parser(pkt):
    '''
    Start parsing packets here
    '''
    global pkt_frag_loads

    # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP):
        pass

    elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
        print pkt.summary()

        ack = str(pkt[TCP].ack)
        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
        load = pkt[Raw].load
        frag_remover(ack, src_ip_port, load)
        pkt_frag_loads[src_ip_port] = frag_joiner(ack, src_ip_port, load)
        full_load = pkt_frag_loads[src_ip_port][ack]

        print ''

def main(args):

    # Check for root
    if geteuid():
        exit('[-] Please run as root')

    #Find the active interface
    if args.interface:
        conf.iface = args.interface
    else:
        conf.iface = iface_finder()

    # Read packets from either pcap or interface
    if args.pcap:
        try:
            pcap = rdpcap(pcap_file)
        except Exception:
            exit('[-] Could not open %s' % pcap_file)
        for pkt in pcap:
            pkt_parser(pkt)
    else:
        sniff(iface=conf.iface, prn=pkt_parser, store=0)


if __name__ == "__main__":
   main(parse_args())
