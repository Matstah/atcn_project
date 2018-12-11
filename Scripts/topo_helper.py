#!/usr/bin/env python

"""
Requires matplotlib:
    python -m pip install -U matplotlib --user
"""
import sys
sys.path.append('/home/p4/atcn-project/Utils')
from TopoHelper import TopoHelper


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--topo', type=str, default='../Project/topology.db', help='Topology database file')
    parser.add_argument('-d', '--draw', action='store_true', required=False, help='Flag: draw topology [DOES NOT WORK ANYMORE]')
    parser.add_argument('-e', '--edge', type=str, required=False, help='Edge label type. Choose from one of [port, ip, mac]')
    parser.add_argument('-i', '--info', action='store_true', required=False, help='Flag: get info of topo')
    parser.add_argument('-t', '--type', type=str, default='all', help='With INFO: show only for one of [external, internal, switches]')
    parser.add_argument('--src', type=str, required=False, help='With INFO: get detailed info for this node as being the source')
    parser.add_argument('--dst', type=str, required=False, help='With INFO and SRC: get even more details towards this node as destination. Can also be "all"')
    args = parser.parse_args()

    if not (args.draw or args.info):
        print('Nothing to do! Choose an option! [help with -h]')

    helper = TopoHelper(args.topo)
    if args.info:
        if args.src:
            helper.details(args.src, args.dst)
        else:
            helper.info(args.type)
    if args.draw:
        helper.draw(args.edge)
    print('-'*10)
