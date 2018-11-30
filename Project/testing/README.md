#testing

## test knock sequence
This sender first send a sequence of udp knocks as specified in the cli. Then it assumes that the secret port has been activated and sends 10 tcp packets to that secret port. The secret port is set in the file itself. It is 3141.

The current secret port combination is set via the firewall_controller, but to be able to pass the gate, the port_knock_controller needs to listen to activate the secret port... The knocking sequence is set in firewall controller and is currently [100, 101, 102, 103] but can be changed in any way...

`sudo python testing/knock_seq_send.py --local --src <srcIP> --dst <dstIP> --sleep <time between knocks> --k <port1> ... <portN> `
`sudo python testing/knock_seq_send.py --local --src <srcIP> --dst <dstIP> --k <port1> ... <portN>`
