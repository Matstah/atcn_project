# Scripts

## topo_helper.py
Get help:
```bash
python topo_helper.py -h
```
Help:
```
-h, --help            show this help message and exit
--topo TOPO           Topology database file [default is a specific file!!]
-d, --draw            Flag: draw topology
-e EDGE, --edge EDGE  Edge label type. Choose from one of [port, ip, mac]
-i, --info            Flag: get info of topo
-t TYPE, --type TYPE  With INFO: show only for one of [external, internal,
                      switches]
--src SRC             With INFO: get detailed info for this node as being
                      the source
--dst DST             With INFO and SRC: get even more details towards this
                      node as destination. Can also be "all"
```

### draw topo

Example Usage:

```bash
python topo_helper.py -d
```

Label the edges with information
```bash
python topo_helper.py -d -e <label_type>
```
where `<label_type>` = port, ip, mac

The topology database file can be provided with --topo if there is a problem with the default path or another file should be used.
```bash
python topo_helper.py -d --topo some/relative/path/topology.db
```
**Note**: If there is a problem, use a topology without any `"cpu_port": true` configured in `p4app.json`. In the `Scripts` folder a 'prepared' topology without cpu ports can be found, which is used as default by the script!!.

### information about topo

Examples:

```bash
python topo_helper.py -i
```

```bash
python topo_helper.py -i -t <type>
```
where `<type>` = internal, external or switches

```bash
python topo_helper.py -i --src <node>
```
where `<node>` = name of a node in the network

```bash
python topo_helper.py -i --src <node> --dst <node>
```
where `--dst` `<node>` = name of a node in the network or `all`. Gives details of things that are interesting from src's viewpoint towards dst.
