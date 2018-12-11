# Scripts

Execute in Scripts folder or use relative path
```bash
cd ~/atcn-project/Scripts
```
The following assumes, that you are in the folder!

Get help:
```bash
python topo_helper.py -h
```

## topo_helper.py

Draw [DOES NOT WORK ANYMORE. EDGE LABELS CANNOT BE SHOWN DUE TO ADDITIONAL SWITCH sw-cpu FOR CLONING] or show information about topology.

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
