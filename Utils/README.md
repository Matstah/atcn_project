# Utils
Import package with
```
rel_path = '/../path/from/script/to/Utils/folder/Utils'
script_path = path.split(path.abspath(__file__))[0]
sys.path.append(script_path + rel_path)
from TopoHelper import TopoHelper
```

## TopoHelper
Usage:
```
from TopoHelper import TopoHelper

helper = TopoHelper('topology.db')
helper.details(src, dst)
helper.info("all")
helper.draw()
```
Note: If there is a problem, use a topology without any `"cpu_port": true` configured in `p4app.json`. In the `Scripts` folder a 'prepared' topology without cpu ports can be found.
