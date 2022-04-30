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
