```
ADAXES Add/Remove/Modify/Run/Create/Execute/Create/Deliver/Send/Signin
    tag1 ; common event
        Add ; Add user to group
        Remove ; Remove user to group
        Run ; Command Executed
        Create ; Create user
        Modify ; Modified user
        Sign in ; User login
        Execute ; Scheduled task executed
        Deliver ; Notification sent
        Create ; Created notification
        Send ; Notification Sent
<USER:(?<severity>[^>]*).*?ADAXES\s(?:(?<vmid>[^\|@]*)|[^(]+\((?<login>[^@]*)\@(?<domainorigin>[^)]*)\))\|(?<vendorinfo>(?<tag1>Add|Remove|Run|Create|Sign in|Change|Modify|Execute|Create|Deliver|Send)\s+(?:(?:\'(?<account>[^(]*)\s(?<group>[^']*)'.*?(?:from|to)\s+'(?<object>[^']*)'|PowerShell\s+script(?:[^']*\'(?<command>[^']*)'\s+for\s+'(?<object>[^']*).*?)|(?:\'(?<account>[^(]*)\s(?<group>[^']*)'.*)|(?:to\sWeb\s+Interface.*?'(?<session>[^']*)'\s+from\s'(?<sip>\d+\.\d+\.\d+\.\d+)')|password\sfor\s\'(?<account>[^(]*)\s(?<group>[^']*).*|HTML\s+document\s'(?<subject>[^']*)'\s(?:to|for)\s+'?(?<account>[^@'\(]*)(?:@|\s)[^\|]*|scheduled\stask\s'(?<subject>[^']*)\'\s+for\s+\'(?<account>[^(]*)\s(?<group>[^']*).*)|e-mail\snotification\s\((?<subject>.*?)'\)))\|(?<result>.*)$

Depending on LogRhythm single-quote/double-quote mix-up
<USER:(?<severity>[^>]*).*?ADAXES\s(?:(?<vmid>[^\|@]*)|[^(]+\((?<login>[^@]*)\@(?<domainorigin>[^)]*)\))\|(?<vendorinfo>(?<tag1>Add|Remove|Run|Create|Sign in|Change|Modify|Execute|Create|Deliver|Send)\s+(?:(?:\"(?<account>[^(]*)\s(?<group>[^"]*)".*?(?:from|to)\s+"(?<object>[^"]*)"|PowerShell\s+script(?:[^"]*\"(?<command>[^"]*)"\s+for\s+"(?<object>[^"]*).*?)|(?:\"(?<account>[^(]*)\s(?<group>[^"]*)".*)|(?:to\sWeb\s+Interface.*?"(?<session>[^"]*)"\s+from\s"(?<sip>\d+\.\d+\.\d+\.\d+)")|password\sfor\s\"(?<account>[^(]*)\s(?<group>[^"]*).*|HTML\s+document\s"(?<subject>[^"]*)"\s(?:to|for)\s+"?(?<account>[^@"\(]*)(?:@|\s)[^\|]*|scheduled\stask\s"(?<subject>[^"]*)\"\s+for\s+\"(?<account>[^(]*)\s(?<group>[^"]*).*)|e-mail\snotification\s\((?<subject>.*?)"\)))\|(?<result>.*)$

ADAXES Base Catch Rule Level 1
ADAXES\s(?:(?<vmid>[^\|@]*)\|(?<vendorinfo>[^\|]*)\|(?<result>.*$)|[^(]+\((?<login>[^@]*)\@(?<domainorigin>[^)]*)\)\|(?<vendorinfo>[^\|]*)\|(?<result>\S+))
```

```
HOST_FILE_DETECTION
user_name\"[^\"]*"(?<login>[^\"]*)\".*?type\"[^\"]*\"(?<vmid>HOST_FILE_DETECTION).*?device_domain":\s+"(?<domain>[^\"]*)\".*?path"[^\"]*\"(?<process>[^\"]*)\"[^\"]*\"creator_process\"[^\"]*\"(?<parentprocessname>[^\"]*)\".*?sha2\"[^\"]*\"(?<hash>[^\"]*)\".*quarantine_uid"[^\"]*\"(?<action>[^\"]*)\".*?device_ip\"[^\"]*\"(?<sip>\d+\.\d+\.\d+\.\d+)\".*?severity_id":\s+(?<severity>\d+)[^\"]*"threat.*?name\"[^\"]*\"(?<vendorinfo>[^\"])*\".*$

APPLICATION_LIFECYCLE|UPDATE|POLICY_CHANGE
timezone.*?(?:user_name\"[^\"]*"(?<login>[^\"]*)\")?,\s"es.mapping.id"[^\"]*\"[^\"]*\"(?:,\s\"[^\"]*"[^\"]*\"[^\"]*\"){2,3}(?:,[^{]*{[^}]*})?,\s+\"type\"[^\"]*\"(?<vmid>APPLICATION_LIFECYCLE|UPDATE|POLICY_CHANGE).*?device_domain":\s+"(?<domain>[^\"]*)\"(?:,\s\"[^\"]*"[^\"]*\"[^\"]*\")(?:,\s\"[^\"]*"[^\"]*\"[^\"]*\")[^\"]*\"device_name\"[^\"]*\"(?<sname>[^\"]*)\".*?\"message\"[^\"]*\"(?<vendorinfo>)[^\"]*\"

SCAN
"es.mapping.id"[^\"]*\"[^\"]*\"(?:,\s\"[^\"]*"[^\"]*\"[^\"]*\"){2,3}(?:,[^{]*{[^}]*})?,\s+\"type\"[^\"]*\"(?<vmid>SCAN)\".*?user_name"[^\"]*\"(?<login>[^\"]*)\".*?message\"[^\"]*\"(?<vendorinfo>[^\"]*)\"

NETWORK_DETECTION
"type":\s?"(?<tag1>NETWORK_DETECTION)".*?connection":\s?{"src_ip":\s+"(?<sip>[^"]+)"?,\s+"src_port":\s+(?<sport>\d+).*?dst_port":\s+(?<dport>\d+).*?src_name":\s+"(?<sname>[^"]*?)",\s?"dst_ip":\s+"(?<dip>[^"]+)"(?:.*?url.*?path":\s+"(?<url>[^"]*)".*?host":\s+"(?<dname>[^"]*))?.*?feature_name":\s+"(?<vmid>[^"]*).*?cybox.*?path":\s+"(?<parentprocesspath>[^"]*)".*?"name":\s+"(?<process>[^"]*)"(?:.*?md5":\s+"(?<hash>[^"]*))?.*?user_name":\s+"(?<login>[^"]*)",\s+"device_domain":\s+"(?<domainorigin>[^"]*)".*?device_name":\s+"(?<sname>[^"]*)".*?device_os_name":\s+"(?<version>[^"]*).*?message":\s+"(?<vendorinfo>[^"]*)"(?:.*cmd_line":\s+"(?<command>.*?),\s+")?

POLICY
user_name":\s+"(?<login>[^"]*).*?message":\s+"(?<vendorinfo>[^"]*).*?session_id":\s+"(?<session>[^"]*)".*?"name":\s+"(?<policy>[^"]*)".*?version":\s+(?<version>\d+)
```

```
OpenGear MPE library

MPE Rule Name: Process Catch-All Level 1
Common Event: Operations : Information : Process Status
Subrule: Process Error ; severity = ERRR
    Common Event : Operations : Error : Process Error
<[^:]+\:(?<severity>[^>]+)\>\s+\S+\s+\d+\s+\d+\:\d+\:\d+\s+(?<sname>\S+)\s+(?<process>[^\[]+)\[(?<processid>\d+)\]\:(?>\s+(?<result>\S+)\s+\S+\s+\-\s+(?<vendorinfo>.*)$|(?<vendorinfo>.*)$)

Sample Log:
03 29 2021 19:01:36 10.13.121.140 <USER:ERRR> Mar 29 19:01:36 CAOL-HQ-Q7004-01 /bin/cellctld[3050]: ERROR    /bin/cellctld - Failed to get cellmodem SMS list
03 29 2021 19:04:06 10.13.121.140 <USER:ERRR> Mar 29 19:04:06 AOL-HQ-Q7004-01 /bin/cellctld[3050]: ERROR    /bin/cellctld - Error getting message list: GDBus.Error:org.freedesktop.DBus.Error.UnknownMethod: No such interface 'org.freedesktop.ModemManager1.Modem.Messaging' on object at path /org/freedesktop/ModemManager1/Modem/0


MPE Rule Name: Process Base Catch-All Level 2
Common Event: Operations : Information : Process Status
<[^:]+\:(?<severity>[^>]+)\>\s+\S+\s+\d+\s+\d+\:\d+\:\d+\s+(?<sname>\S+).*?(?>kernel\:\s+\S+|\s+)(?<process>[^:]+)\:\s+(?<vendorinfo>.*)$

Sample Log:
03 29 2021 19:01:39 10.1.121.6 <KERN:WARN> Mar 29 19:01:39 AOL-HQ-Q7004-01 kernel: [6078770.225562] Iptables: Block: IN=eth0 OUT= MAC=8:00 SRC=10.1.4.4 DST=10.1.1.6 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=671 DF PROTO=TCP SPT=60504 DPT=135 WINDOW=14600 RES=0x00 SYN URGP=0 
03 29 2021 19:59:01 10.13.121.140 <SLOG:INFO> Mar 29 19:59:01 AB-TAY-Q7248-01 syslog:  [origin software='rsyslogd' swVersion='8.33.0' x-pid='135' x-info='http://www.rsyslog.com'] rsyslogd was HUPed
```

```
MPE: Canary Catch-All 
eventid="(?<vmid>[^"]+)\"\s+(?:ReverseDNS="(?<sname>[^\"]+)\"\s+CanaryName="(?<dname>[^\"]+)\"\s+.*?Description="(?<subject>[^"]+)\".*?Flock="(?<group>[^"]+)\"\s+CanaryIP="(?<dip>\d+\.\d+\.\d+\.\d+)\"\s+)?.*?SourceIP="(?<sip>\d+\.\d+\.\d+\.\d+)(?:.*?IncidentHash="(?<hash>[^"]+))?\".*?AdditionalIncident.*?\]\s\S{3}(?<vendorinfo>.*$)
    vmid="1004" - Canary Disconnected/Reconnected
        Security : Activity : AIE : Honeypot : Activity
    vmid="5007" - Consolidated Network Port Scan
        Security : Reconnaissance : Port Scan
    vmid="20001" - Custom TCP Service Request
        Security : Activity : TCP Service Sweep
    vmid="19001" - Git Repository Clone Attempt
    vmid="5003" - Host Port Scan
        Security : Reconnaissance : Port Scan
    vmid="18001" - ModBus Request
        Security : Activity : MODBUS Write Command
    vmid="5005" - Nmap NULL Scan // vmid="5008" - Nmap FIN Scan // vmid="5004" - Nmap OS Scan // vmid="5006" - Nmap Xmas Scan
        Security : Activity : Nmap OS Fingerprint
    vmid="11011" - NTP Monlist Request
    vmid="21001" - Redis Command
    vmid="15001" - SIP Request
        Security : Activity : SIP Detected
    vmid="13001" - SNMP
        Security : Activity : SNMP Activity
    vmid="10001" - TFTP Requst
        Security : Activity : Web TFTP Detected
    vmid="12001" - VNC Login Attempt
        Security : Activity : VNC Detected
MPE: Canary Shared File Opened
vmid="5005" - Shared File Opened
    eventid="(?<vmid>5000)\"\s+(?:ReverseDNS="(?<sname>[^\"]+)\"\s+CanaryName="(?<dname>[^\"]+)\"\s+.*?Description="(?<subject>[^"]+)\".*?Flock="(?<group>[^"]+)\"\s+CanaryIP="(?<dip>\d+\.\d+\.\d+\.\d+)\"\s+)?.*?SourceIP="(?<sip>\d+\.\d+\.\d+\.\d+)(?:.*?IncidentHash="(?<hash>[^"]+))?\".*?AdditionalIncident(?:.*?Filename="(?<object>[^"]+)\")?.*?\]\s\S{3}(?<vendorinfo>.*$)
        Operations : Information : File Opened
MPE: Canary Authentication Attempt
vmid="2000" - FTP Login Attempt // vmid="3001" - HTTP Login // vmid="7001" - HTTP Proxy Request // vmid="9001" - Microsoft SQL Server Login // vmid="8001" - MySQL Login // vmid="4002" - SSH (Password login) / SSH (key-based login) // vmid="6001" - Telnet Login Attempt // vmid="28000" - Mongo Authentication Attempt
    eventid="(?<vmid>2000|3001|7001|9001|8001|4002|6001)\"\s+(?:ReverseDNS="(?<sname>[^\"]+)\"\s+CanaryName="(?<dname>[^\"]+)\"\s+.*?Description="(?<subject>[^"]+)\".*?Flock="(?<group>[^"]+)\"\s+CanaryIP="(?<dip>\d+\.\d+\.\d+\.\d+)\"\s+)?.*?SourceIP="(?<sip>\d+\.\d+\.\d+\.\d+)(?:.*?IncidentHash="(?<hash>[^"]+))?\".*?AdditionalIncident.*?(?:Username|User)=\"(?<login>[^"]+)\"(?:.*?URL=\"(?<url>[^"]+)\")?(?:).*?User-Agent="(?<useragent>[^"]+)\")?.*?\]\s\S{3}(?<vendorinfo>.*$)
        Security : Activity : Authentication Attempt
MPE: Canary Settings Changed
vmid="23002" - Canary Settings Changed
    eventid="(?<vmid>2000|3001|7001|9001|8001|4002|6001)\"\s+(?:ReverseDNS="(?<sname>[^\"]+)\"\s+CanaryName="(?<dname>[^\"]+)\"\s+.*?Description="(?<subject>[^"]+)\".*?Flock="(?<group>[^"]+)\"\s+CanaryIP="(?<dip>\d+\.\d+\.\d+\.\d+)\"\s+)?.*?SourceIP="(?<sip>\d+\.\d+\.\d+\.\d+)(?:.*?IncidentHash="(?<hash>[^"]+))?\".*?AdditionalIncident.*?Username=\"(?<login>[^"]+)\"(?:.*?URL=\"(?<url>[^"]+)\")?(?:).*?User-Agent="(?<useragent>[^"]+)\")?(?:.*?Hostname="(?<dname>[^"]+)\")?\]\s\S{3}(?<vendorinfo>.*$)
        Operations : Information : Config Changed on Interface
```
