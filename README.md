# Test Deployment for Flow Processing with OpenNMS

The provided Docker Compose will start a single instance of the following components:

* Cassandra (for OpenNMS)
* Zookeeper (for Kafka)
* Kafka
* Elasticsearch with the provided Drift plugin (version must match)
* Kibana (port 5601 exposed)
* PostgreSQL
* OpenNMS (ports 8980 and 8101 exposed)
* Minion (ports 9999 and 8201 exposed)
* Sentinel (port 8301 exposed)
* Grafana with OpenNMS Helm (port 3000 exposed)

> The focus here is flows, which is why the persistence of Streaming Telemetry data in Cassandra for Sentinel is not enabled.

Once everything is running, you can configure your flow generator to send flows to your Docker Host at port 9999, and the Minion will receive and process them. Keep in mind that when running Docker for Mac or Docker for Windows, due to the network behavior, UDP packets will appear as coming from the gateway address instead of the flow sender IP address. The following can be used to get that IP

```bash
docker network inspect flows-overview_default \
  --format "{{ json .IPAM.Config }}" | jq -r '.[].Gateway'
```

When building the requisition in OpenNMS, you must add that IP to the node that represents the flow sender node. This is crucial to let Sentinel know how to enrich flows and OpenNMS to find the interface from the flow sender from which the flows were received.

# Flow Generator/Sender

As having a router or switch with flow-sending capabilities can be hard to have at home, the easiest way to have a flow sender is using a tool called `pmacctd` from the [pmacct](http://www.pmacct.net/) project. That tool can be compiled/installed on macOS or Linux.

Once installed, the following article from OpenNMS Discourse can help you configure the tool:

https://opennms.discourse.group/t/how-to-use-pmacct-as-a-netflow-9-probe-on-ubuntu-linux-and-mac-os-big-sur/1160/3

Here is how I configured it:

```bash
❯ cat /opt/pmacct/cfg/pmacctd.conf
# https://github.com/pmacct/pmacct/blob/master/CONFIG-KEYS
daemonize: false
debug: true
interface: en0
aggregate: src_host, dst_host, src_port, dst_port, proto, tos
plugins: nfprobe[en0]
nfprobe_receiver: localhost:9999
nfprobe_version: 9
nfprobe_direction[en0]: tag
nfprobe_ifindex[en0]: tag2
pre_tag_map: /opt/pmacct/cfg/pretag.map
timestamps_secs: true
```

I'm running the process in the foreground (`daemonize: false`), showing DEBUG messages (`debug: true`), and inspecting the WiFi NIC on my Mac (`interface: en0`) to generate flows from the packets it is observing (as `pmacctd` should put the interface in promiscuous or monitor mode). The flows will be forwarded to port 9999 locally (`nfprobe_receiver: localhost:9999`) using NetFlow 9 (`plugins: nfprobe[en0]` and `nfprobe_version: 9`).

The direction and ifindex configuration are crucial and are configured on `pretag.map` file, which has the following content:

```
# Use a filter to determine the direction
# Set 1 for ingress and 2 for egress
#
# Local MAC
set_tag=1 filter='ether dst 00:00:00:00:00:00' jeq=eval_ifindexes
set_tag=2 filter='ether src 00:00:00:00:00:00' jeq=eval_ifindexes

# Use a filter to set the ifindexes
set_tag2=6 filter='ether src 00:00:00:00:00:00' label=eval_ifindexes
set_tag2=6 filter='ether dst 00:00:00:00:00:00'
```

Besides updating the MAC Address to your needs (in my case the address for `en0`), you must update the number right after `set_tag2` to be the `ifIndex` of your interface. On macOS, the easiest way is to have `snmpd` running, so you can monitor your host via SNMP and locate the interface index:

```
❯ snmpwalk -v 2c -c public 192.168.0.100 ifDescr | grep en0
IF-MIB::ifDescr.6 = STRING: en0
```

As you can see, the `ifIndex` is 6.

The reference article explains how to do it on Linux.

To run the tool:

```bash
sudo /opt/pmacct/sbin/pmacctd -f /opt/pmacct/cfg/pmacctd.conf
```

# OpenNMS Configuration.

First, configure `snmpd` and use `public` for the community string on your machine, and ensure it is running.

Then, use the following as an example of how to build the requisition for the flow generator/sender, assuming it is running directly on your machine.

```bash
GATEWAY_IP=$(docker network inspect flows-overview_default \
  --format "{{ json .IPAM.Config }}" | jq -r '.[].Gateway')

LOCAL_INTF="en0"
LOCAL_IP=$(ifconfig $LOCAL_INTF | grep "inet " | awk '{print $2}')

cat <<EOF >/tmp/requisition.json
{
  "foreign-source": "Home",
  "node": [
    {
      "location": "Docker",
      "foreign-id": "macos-host",
      "node-label": "macos-host",
      "interface": [
        {
          "ip-addr": "$LOCAL_IP",
          "descr": "$LOCAL_INTF",
          "snmp-primary": "P"
        },
        {
          "ip-addr": "$GATEWAY_IP",
          "descr": "Docker/NAT",
          "snmp-primary": "N"
        }
      ]
    }
  ]
}
EOF

curl -v -u "admin:admin" \
  -H "Content-Type: application/json" -d @/tmp/requisition.json \
  http://localhost:8980/opennms/rest/requisitions

cat <<EOF >/tmp/foreignsource.json
{
  "name": "Home",
  "scan-interval": "1d",
  "detectors": [
    {
      "name": "ICMP",
      "class": "org.opennms.netmgt.provision.detector.icmp.IcmpDetector"
    },
    {
      "name": "SNMP",
      "class": "org.opennms.netmgt.provision.detector.snmp.SnmpDetector"
    }
  ],
  "policies": []
}
EOF

curl -v -u "admin:admin" \
  -H "Content-Type: application/json" -d @/tmp/foreignsource.json \
  http://localhost:8980/opennms/rest/foreignSources

curl -v -u "admin:admin" -X PUT \
  http://localhost:8980/opennms/rest/requisitions/Home/import
```

> Remember to change the above according to your environment. The above assumes `snmpd` is running and configured correctly, using `public` for the community string.

# Verification

You can check the Elasticsearch Indices via Kibana or look at the Flows Dashboard on Grafana after a few minutes of importing the node.
