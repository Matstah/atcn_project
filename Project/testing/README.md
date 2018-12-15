# Testing

## test port knocker
This sender first send a sequence of udp knocks as specified in the cli. Then it assumes that the secret port has been activated and sends 10 tcp packets to that secret port. The secret port is set in the file itself. It is 3141.

The current secret port combination is set via the firewall_controller, but to be able to pass the gate, the port_knock_controller needs to listen to activate the secret port... The knocking sequence is set in firewall controller and is currently [100, 101, 102, 103] but can be changed in any way... The only limit is the number of knocks in the sequence due to the bit size of the counter in p4. Can be changed there..

```
sudo python knock_seq_send.py --local --src he2 --dst hi2 -k 100 101 102 103 -s 3142
```
or
```
sudo python knock_seq_send.py --local --src <srcName> --dst <dstName> -k <knock sequence> -s <secret port>
```

## client and server (TCP handshake)
### server
The server script is supposed to run on the `ser` host, but the server can basically run anywhere (from the firewall's view), but the scripts are written towards this use case.
```
sudo python server.py --local --debug
```
The server expects a tcp handshake from a single host and then 'acks' (and prints) the data content that it receives from the host.

### client
The client tries to establish a connection with the server and then sends some data packets. The firewall will reset the first handshake and set the client to the whitelist. The client will simply try again.
After a successful handshake (which it can only do, when it reaches the server) it will send some data packets to the server.

### Bad modes
Both scripts have a 'bad' mode. To activate in both scripts, set the option `--bad`.
For the **client** this means, that he will send only SYN packets after a successful handshake with the server.
For the **server**, this means, that he expects the bad behavior and instead of acking the packets from the client, he will print the received SYNs to show the firewalls funtion. After a while, the firewall should detect this attack, and you should not see the SYN packets anymore on the server side.

## syn flood
The syn flood script iterates through the subnet 10.0.3.0/24 in 5 phases and just send SYN packets with random source ports. This can be run parallel with the client script to show, that the firewall does not let the bad traffic through, but the client eventually gets through.
