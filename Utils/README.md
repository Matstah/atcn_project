# Utils
Import package with
```
import sys
sys.path.append('/home/p4/atcn-project/Utils')
```
!! Adjust path according to your structure !!

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
