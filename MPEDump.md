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
