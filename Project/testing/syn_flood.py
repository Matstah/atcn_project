#!/usr/bin/env python
from __future__ import print_function
import os
import argparse
import sys
import socket
import random
import struct
import logging as log

from p4utils.utils.topology import Topology
from scapy.all import *
import time
import re

host = 'he3'

if '--local' in sys.argv:
    print('start on remote...')
    from subprocess import call
    cmd = ["mx", host, 'python', sys.argv[0]]
    call(cmd)
    exit(0)
else:
    print('On %s: let\'s go' % host)

ip_base = '10.0.3.'
ser_ip = '10.0.4.4'
phases = 5

eth = Ether(src='00:00:0a:00:04:03', dst='00:00:0a:00:04:04')

for phase in range(phases):
    print('phase ' + str(phase+1))
    for i in range(256):
        packet = eth/IP(src=ip_base + str(i), dst=ser_ip)/TCP(sport=RandShort(), dport=80, flags="S")
        print('.', end='')
        sys.stdout.flush() # print point immediately
        sendp(packet, verbose=0)
    print('')
