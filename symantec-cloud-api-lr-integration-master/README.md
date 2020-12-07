# Symantec Cloud API LR Integration


Build a Custom Log Source Type: API - Symantec Cloud

Deployment Manager -> Tools -> Knowledge -> Log Source Type Manager -> New (+)
```
    Name: API - Symantec Cloud
    Full Name: API - Symantec Cloud
    Abbreviation: Symantec Cloud
    Log Format: Text File
    Brief Description: API - Symantec Cloud
    Additional Details:
```
New Date Format Property:
```
    Name: Symantec Cloud
    Regex: <yy>-<M>-<d>T<h>:<m>:<s>
    Description: Symantec Cloud
```

Add the following MPEs to the LogRhythm MPE Rule Builder:

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
