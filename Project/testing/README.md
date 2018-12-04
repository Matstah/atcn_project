#testing

## test knock sequence
This sender first send a sequence of udp knocks as specified in the cli. Then it assumes that the secret port has been activated and sends 10 tcp packets to that secret port. The secret port is set in the file itself. It is 3141.

The current secret port combination is set via the firewall_controller, but to be able to pass the gate, the port_knock_controller needs to listen to activate the secret port... The knocking sequence is set in firewall controller and is currently [100, 101, 102, 103] but can be changed in any way...

`sudo python testing/knock_seq_send.py --local --src <srcIP> --dst <dstIP> --sleep <time between knocks> --k <port1> ... <portN> `
`sudo python testing/knock_seq_send.py --local --src <srcIP> --dst <dstIP> --k <port1> ... <portN>`

## client and server (TCP handshake)
### server
The server script is supposed to run on the `ser` host, but the server can basically run anywhere, but the scripts are written towards this use case.
```
sudo python server.py --local
```
The server expects a tcp handshake from a single host and then 'acks' the data content that it receives from the host.

### client
The client tries to establish a connection with the server and then sends some data packets.
TODO: check if a fin packet arrives and then try again to test getting through the firewall!
