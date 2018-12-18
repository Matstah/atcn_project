# File Organization
The main README is `Project/README.md` where you can test the project immediately and get a lot of information as well.

<pre>
**reduced view**
├── Project
│   ├── **see below**
├── Report
├── Scripts
│   └── topo_helper.py
└── Utils
    ├── TopoHelper.py
</pre>

## Project
See comments enclosed in \*.
<pre>
├── commands                              *Contain table entries
│   ├── fir-commands.txt                  for basic forwarding
│   ├── ge1-commands.txt                  in fir and "gateways"*
│   ├── ge2-commands.txt
│   └── ge3-commands.txt

├── controller                            *three main controllers*
|   ├── legacy/*                          *legacy controllers when all functions
                                            were separate*
│   ├── Dpi.py                            *helper for sniff_controller*
│   ├── firewall_controller.py            *sets actions, register values, etc*
│   ├── heavy_hitter_controller.py        *runs loop to reset heavy hitter filter*
│   ├── sniff_controller.py               *sniffs cloned pkts and acts according to type*
│   └── table_files
│       └── *created by controller*       *if a src got validated and
                                          controller (sniff) stops,
                                          the entries are saved here*
│   ├── dpi_log
│   │   ├── *created by controller*       *log files for DPI are saved
                                          here*

├── filters                               *files read by firewall_controller
│   ├── ext2in_blacklist_srcIP.txt        and sets table entries in firewall*
│   ├── ext2in_whitelist_tcp_dst_ports.txt
│   └── in2ext_blacklist_dstIP.txt

├── p4app.json                            *Definitions for p4run: p4other and p4src*

├── p4other                               *Simple repeater logic for "gateways"*
│   ├── ingress
│   │   ├── apply.p4
│   │   └── mac_translation.p4
│   ├── repeater.p4

├── p4src                                 *P4 program for firewall*
                                          *we have split the program into files
                                          according to functionality*
│   ├── egress
│   │   └── apply.p4
│   ├── firewall.p4                       *basic file that "includes" the others*
│   ├── include
│   │   ├── definitions.p4
│   │   ├── headers.p4                    *ALL CODE IS HEAVILY COMMENTED*
│   │   └── parsers.p4
│   └── ingress
│       ├── apply.p4
│       ├── dpi.p4
│       ├── egress_filter.p4
│       ├── hash.p4
│       ├── ingress_filter.p4
│       ├── ip_forwarding.p4
│       ├── port_knocking.p4
│       └── syn_defense.p4

├── testing                             *test scripts for evaluation and demo*
│   ├── client.py
│   ├── knock_seq_send.py
│   ├── receive.py
│   ├── send.py
│   ├── server.py
│   └── syn_flood.py

└── topology.db                         *created by p4run*
</pre>

## Report
TODO: maybe put final pdf here

## Scripts & Utils
**Note**: Was used in the beginning to gather information of the topology. For example to get all information of a host to check if our setup does what is expected (e.g. write correct MAC address, etc.)

Utils contains `TopoHelper` which gathers some useful information about the topology. Scripts contains a script that uses the TopoHelper module to display information or draw the topology.
