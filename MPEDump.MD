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
