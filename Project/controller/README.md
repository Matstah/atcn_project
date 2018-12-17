# Controllers
All these scripts can be found at `~/atcn-project/Project/controller` and the commands are expected to be executed from there as in the following documentation.

| controller | short description |
| -------- | -------- |
| firewall_controller  | Controller to de- / activate functionalities or set other parameters.   |
| sniff_controller   |  The "brain" that handles cloned packets from firewall.   |
| heavy_hitter_controller | Loops endlessly and resets filter for heavy hitter detection. |

This structure gives user the ability to interact with the firewall without stopping the whole thing. The general idea is the following:
1. Start firewall_controller with no arguments, which sets the default values, which are generally useful. (Although we set default values that serve the purpose of testing and demonstration.)
2. Start sniff_controller, which does all the work on its own. Only receives packets from firewall if the functionality is activated.
3. Start heavy_hitter_controller that runs endlessly.
4. During operation change parameters of the functions or de-/activate as needed with firewall_controller.


## firewall_controller.py
General use:
```
sudo python firewall_controller.py
```
Help:
```
--no_dpi
  Deactivate dpi

--dpi_prob | -dp DPI_PROB
  Set inspection probability [%]

--no_knock
  deactivate knock

--knock_sequence | -ks KNOCK_SEQUENCE [KNOCK_SEQUENCE ...]
  define port knocking sequence

--knock_timeout  | -kt KNOCK_TIMEOUT
  set timeout [s] between knocks

--no_filter
  Clear all filter tables

--filter_clear   | -fc FILTER_CLEAR [FILTER_CLEAR ...]
  clear specified filter from ['wp','bs','bd']

--filter_set     | -fs FILTER_SET [FILTER_SET ...]
  set only specified filter form [wp,bs,bd]

  wp = 'whitelist_tcp_dst_port'
  bs = 'blacklist_src_ip'
  bd = 'blacklist_dst_ip'
```
Examples (only arguments shown, with explanation):
```
--no_dpi                   deactivate dpi
-dp 50                     set dpi probability to 50%
-ks 100 50 150 300 -kt 3   define new knock sequence with timeout of 3 seconds
-fc bs bd                  clear the two blacklist tables
-fc bs -fs bs              reset blacklist: 1. clear, 2. fill with default from file
                           e.g. good to test synflood mechanism again from same
                           source because validation is not possible if blacklisted
-fs wp -fc bs -dp 70       change multiple things at once
```
Our default values:
```
dpi_prob:           100%
knock_sequence:     100 101 102 103
knock_timeout:      5 seconds
filter:             set all filters
```

##### Filters: Black- and Whitelists:
There are two blacklists. One that looks at dst ip address for traffic from intern to extern. The other blacklist looks at source ip of traffic from extern to intern. On both lists we use ranges of ip to define what should be blocked. The whitelist is for dst ports from extern to intern traffic. Currently he1 is blocked on both directions, and port 80 and 110 is open.

##### Deep Packet Inspection (DPI):
The dpi probability decides how likely a flow gets selected with the first (internal!) SYN packet. The *sniff_controller* logs the chosen flows.

##### Port Knocking:
The *firewall_controller* sets up a port knocking tracker on the switch via table entries. The timeout defines the maximal time a _knocker_ can take in between knocks.

All UDP traffic, that can not pass the stateful firewall will be dropped by the firewall, independently of these settings.


## sniff_controller.py
Simply use with:
```
sudo python sniff_controller.py
```
This controller sniffs all cloned packets from the firewall and only stops if the user terminates the script. There are four clone scenarios:
1. Packet for inspection that the controller should log.
2. Successful knock sequence, so the controller should grant access to this source.
3. A source got validated by the SYN-flood defense mechanism. The controller has to grant access for this source.
4. If a validated source as above in 3. gets malicious (SYN-flooding as detected by heavy hitter detector), the address must be removed from validation list and gets blacklisted from now on.

**DPI**:
DPI packets get written to files in the following format in the subdirectory `./dpi_log` (which is created if it does not exit):
```
dpi_<ip1>and<ip2>-flow<id>_num<count>
dpi_10.0.4.4and10.0.3.1-flow473_num1
```
 One can see the two parties of the communication with `ip1` and `ip2` directly in the filename. The flow id is also shown in the name. The numeration shows that at some point the flow was forgotten due to a timeout and a new flow was detected and logged in a new file.
 You can easily follow an ongoing flow with:
 ```
 tail -f dpi_log/dpi_10.0.4.4and10.0.3.1-flow473_num1
 ```

**Knocking**:
This script also sets the *secret port*, which will be opened to a specific source once a correct knocking sequence has been recorded (see 2.). The secret port is _hardcoded_ to `3141`. If you want to change it, you can adapt the script at the beginning and restart the controller.

**Source Validation**:
1. Grant access packet: The appropriate table entry gets written which returns an ID that is saved in a dictionary.
2. Revoke access packet: The validation of a client has to be revoked, so the controller deletes the entry in the table from 1. with the saved ID. Additionally, the client gets blacklisted.

If the controller terminates and there are valid sources saved in the dictionary, it is saved in a pickle file as `./table_files/source_accepted.pkl`. If the dictionary is empty, the file is deleted (if there was one to begin with). With each start of the controller the file is loaded (if available) and stored in the dictionary. If you restart the whole architecture with `p4run`, make sure that there is _no_ file in `./table_files` or remove the directory entirely.

## heavy_hitter_controller.py
This scripts connects to the firewall and then stays in a loop. Every `5` seconds (hardcoded!) it resets the bloom filter of the heavy hitter detector for validated sources. This means that a validated source cannot send an amount of SYN packets that exceeds the threshold on the firewall (also hardcoded to low `10` because it is easier to show in a demo, but should be chosen and based on the application behind the firewall).
