# Utils

Execute in Utils folder or use relative path
```bash
cd ~/atcn-project/Utils
```
The following assumes, that you are in the folder!

Get help:
```bash
python topo_helper.py -h
```

## topo_helper.py

Draw or show information about topology.

### draw topo

Example Usage:

```bash
python topo_helper.py -d
```

or the topology database file can be provided with --topo
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
