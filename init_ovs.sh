#!/bin/bash
/etc/init.d/openvswitch-switch start </dev/null

if [ $# -eq 1 ]; then
	CADDR=$1
else
	echo "Usage: init_ovs.sh <controller-ipv4-address>"
	exit 1
fi

# Set the host number and create the OVS database file
HOST_NUM=${NODE_NUMBER}
CONF_DIR="/etc/openvswitch"
DB_FILE="$CONF_DIR/conf-$HOST_NUM.db"
cp $CONF_DIR/conf.db $DB_FILE

# Start the OVS database server
ovsdb-server --remote=punix:db.sock \
             --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
             --private-key=db:Open_vSwitch,SSL,private_key \
             --certificate=db:Open_vSwitch,SSL,certificate \
             --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
             --pidfile=ovsdb-server.pid \
             --detach \
             --log-file=ovsdb-server.log $DB_FILE

# Start the OVS daemon
ovs-vswitchd --pidfile=ovs-vswitchd.pid \
             --detach \
             --log-file=ovs-vswitchd.log unix:db.sock

# Create the bridge and set controller properties
ovs-vsctl --no-wait add-br br0
ovs-vsctl set bridge br0 fail-mode=secure
ovs-vsctl set-controller br0 tcp:$CADDR:6633
ovs-vsctl set controller br0 connection-mode=out-of-band

echo -e "\e[33mController @ $CADDR\e[m"

IF_COUNT=$(( `ip link show | grep ": eth" | wc -l` - 2))
for i in `seq 0 $IF_COUNT`; do
    echo "\e[34mAdding eth$i -> br0 @ port $(($i + 1))\e[m"
    ovs-vsctl add-port br0 eth$i -- set interface eth$i ofport_request=$(($i + 1))
done
