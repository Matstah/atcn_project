# Utils
Import package with
!! Adjust path according to your structure !!

```
import sys
sys.path.append('/home/p4/atcn-project/Utils')
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
