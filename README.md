# Grok Parsing of SRX logs

## Unstructured

Parsing unstructured SYSLOG from SRX

### Junos Config

Set format:

```sh
set groups Logstash system syslog host 192.168.108.21 any info
set groups Logstash system syslog host 192.168.108.21 port 30514
set groups Logstash system syslog host 192.168.108.21 source-address 192.168.108.1
set groups Logstash security log stream app-track-logs host 192.168.108.21
```

### Example SYSLOG message

```syslog
<14>Apr 28 10:57:14 firewall1 RT_FLOW: APPTRACK_SESSION_CREATE: AppTrack session created 192.168.105.3/59896->192.168.106.163/443 junos-https UNKNOWN UNKNOWN 192.168.105.3/59896->192.168.106.163/443 N/A N/A 6 lab_vmware lab vmware 111547 N/A N/A UNKNOWN reth1.106 N/A N/A N/A N/A
```

### Grok pattern

```bash
<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}?: %{DATA:apptrack_status}?: %{IP:SRC_IP}/%{DATA:SRC_PORT}->%{IP:DST_IP}/%{WORD:DST_PORT} %{DATA:APP} UNKNOWN %{IP:SRC_NAT_IP}/%{DATA:SRC_NAT_PORT}->%{IP:DST_NAT_IP}/%{DATA:DST_NAT_PORT} %{DATA:RULE} %{DATA:UNKNOWN} %{NUMBER:PROTO_CODE} %{DATA:RULE_POLICY} %{DATA:SRC_ZONE} %{DATA:DST_ZONE} %{NUMBER:BYTES} %{GREEDYDATA:syslog_message}
```

## Structured

Structured output makes the parsing easier to support

### Junos Config

Set format:

```sh
set groups Logstash system syslog host 192.168.108.21 any info
set groups Logstash system syslog host 192.168.108.21 port 30514
set groups Logstash system syslog host 192.168.108.21 source-address 192.168.108.1
set groups Logstash system syslog host 192.168.108.21 structured-data brief
set groups Logstash security log stream app-track-logs host 192.168.108.21
```

### Example SYSLOG message

```syslog
<14>1 2022-04-30T13:22:15.226Z firewall0 RT_FLOW - APPTRACK_SESSION_CREATE [junos@2636.1.1.1.2.135 source-address="192.168.105.3" source-port="44406" destination-address="192.168.106.163" destination-port="443" service-name="junos-https" application="UNKNOWN" nested-application="UNKNOWN" nat-source-address="192.168.105.3" nat-source-port="44406" nat-destination-address="192.168.106.163" nat-destination-port="443" src-nat-rule-name="N/A" dst-nat-rule-name="N/A" protocol-id="6" policy-name="lab_vmware" source-zone-name="lab" destination-zone-name="vmware" session-id="55834617386" username="N/A" roles="N/A" encrypted="UNKNOWN" destination-interface-name="reth1.106" category="N/A" sub-category="N/A" src-vrf-grp="N/A" dst-vrf-grp="N/A"]
```

### Grok parser

```sh
<%{POSINT:FACILITY}>%{INT:PRIORITY} %{DATA:TIMESTAMP} %{DATA:HOSTNAME} %{DATA:PROCESS} %{DATA:PROCESS_ID} %{DATA:APPTRACK_STATUS} %{DATA:RECORD_ID} source-address="%{IP:SRC_IP}" source-port="%{INT:SRC_PORT}" destination-address="%{IP:DESTINATION_IP}" destination-port="%{INT:DST_PORT}" service-name="%{DATA:SERVICE_NAME}" application="%{DATA:APP_NAME}" nested-application="%{DATA:NESTED_APP}" nat-source-address="%{IP:NAT_SRC_IP}" nat-source-port="%{INT:NAT_SRC_PORT}" nat-destination-address="%{IP:NAT_DST_IP}" nat-destination-port="%{INT:NAT_DST_PORT}" src-nat-rule-name="%{DATA:SRC_NAT_RULE_NAME}" dst-nat-rule-name="%{DATA:SRC_DST_RULE_NAME}" protocol-id="%{INT:PROTOCOL_ID}" policy-name="%{DATA:POLICY_NAME}" source-zone-name="%{DATA:SRC_ZONE_NAME}" destination-zone-name="%{DATA:DST_ZONE_NAME}" session-id="%{POSINT:SESSION_ID}" username="%{DATA:USERNAME}" roles="%{DATA:ROLES}" encrypted="%{DATA:ENCRYPTED}" destination-interface-name="%{DATA:DST_IFACE}" category="%{DATA:CATEGORY}" sub-category="%{DATA:SUB_CATEGORY}" src-vrf-grp="%{DATA:SRC_VRF_GROUP}" dst-vrf-grp="%{DATA:DST_VRF_GROUP}"
```
