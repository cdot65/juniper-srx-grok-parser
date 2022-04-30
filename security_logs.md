# Grok Parsing of SRX logs

## Unstructured

### Junos Config

Set format

```sh
set groups Logstash system syslog host 192.168.108.21 any info
set groups Logstash system syslog host 192.168.108.21 port 30514
set groups Logstash system syslog host 192.168.108.21 source-address 192.168.108.1
set groups Logstash system syslog host 192.168.108.21 structured-data brief
set groups Logstash security log stream app-track-logs host 192.168.108.21
```

JSON

```sh
cdot@firewall0> show configuration groups Logstash | display json
```

```json
{
    "configuration" : {
        "@" : {
            "junos:commit-seconds" : "1651315475", 
            "junos:commit-localtime" : "2022-04-30 10:44:35 UTC", 
            "junos:commit-user" : "cdot"
        }, 
        "groups" : [
        {
            "name" : "Logstash", 
            "system" : {
                "syslog" : {
                    "host" : [
                    {
                        "name" : "192.168.108.21", 
                        "contents" : [
                        {
                            "name" : "any", 
                            "info" : [null]
                        }
                        ], 
                        "port" : 30514, 
                        "source-address" : "192.168.108.1", 
                        "structured-data" : {
                            "brief" : [null]
                        }
                    }
                    ]
                }
            },                          
            "security" : {
                "log" : {
                    "stream" : [
                    {
                        "name" : "app-track-logs", 
                        "host" : {
                            "ipaddr" : "192.168.108.21"
                        }
                    }
                    ]
                }
            }
        }
        ]
    }
}
```

### Grok pattern

```bash
<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}?: %{DATA:apptrack_status}?: %{IP:SRC_IP}/%{DATA:SRC_PORT}->%{IP:DST_IP}/%{WORD:DST_PORT} %{DATA:APP} UNKNOWN %{IP:SRC_NAT_IP}/%{DATA:SRC_NAT_PORT}->%{IP:DST_NAT_IP}/%{DATA:DST_NAT_PORT} %{DATA:RULE} %{DATA:UNKNOWN} %{NUMBER:PROTO_CODE} %{DATA:RULE_POLICY} %{DATA:SRC_ZONE} %{DATA:DST_ZONE} %{NUMBER:BYTES} %{GREEDYDATA:syslog_message}
```
