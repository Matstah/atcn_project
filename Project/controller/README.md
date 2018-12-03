# Controllers
All these scripts can be found at `~/atcn-project/Project/controller` and the commands are expected to be executed from there in the following documentation.

## firewall_controller.py
TODO


## dpi_controller.py
The script manipulates registers on the firewall, which affects the control flow of the p4 program. If either or both options (DPI and debugging) are used, the p4 program clones the packets and sends them to the controller.
When the script terminates, the register values are reset to disable the functionality on the firewall.

### DPI
This controller can set the probability for which a flow gets selected with the first SYN packet and then log certain flows according to it. For example for a probability of 50%:
```
sudo dpi_controller.py -p 50
```
sets the probability to 50% by setting the appropriate register on the firewall. From then on the firewall will select with a probability of 50% if a new flow should be monitored. If yes, the firewall will clone the packets of the flow and send them to the controller. The controller then logs the flow in a file of the following format in `./dpi_log`:
```
dpi_<time>_<ip1>and<ip2>-flow<id>
dpi_1543581262_10.0.1.1and10.0.4.1-flow823
```
where one can see the two parties of the communication with `ip1` and `ip2` directly in the filename. The flow id is also shown in the name. The start time ensures, that for a new start of the controller a new file is written. Additionally this gives an immediate hint to the user, when the flow started and the files are ordered by creation time inherently.
Separate files per flow also gives the ability to follow a inspected flow live with:
```
tail -f dpi_log/dpi_1543581262_10.0.1.1and10.0.4.1-flow823
```

### Debugging functionality
Additionally, the DPI functionality can be abused for debugging. If the controller is started as
```
sudo dpi_controller.py -d
```
no files are logged, but all packets are cloned by the firewall and the controller prints the contents directly in the command line.

The two functionalities can be started together, where still only certain flows are logged according to the provided probability, but all packages regardless are printed. For example:
```
sudo dpi_controller.py -p 20 -d
```
