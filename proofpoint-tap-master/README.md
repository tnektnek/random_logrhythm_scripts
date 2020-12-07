# Proofpoint TAP
Clicks Permitted
```
CLKPER.*?recipient=\"(?<login>(?<login>[^@]+)@(?<domainorigin>[^"]+)|[^\"]+)?\"\s+sender=\"(?<object>(?<object>(?<account>[^@]+)@(?<domain>[^\"]+))|[^\"]+)?\"\s+senderIP=\"(?<sip>(?<sip>\d+\.\d+\.\d+\.\d+)|[^\"]+)?\".*?url=\"(?<url>[^\"]+)\".*clickIP=\"(?<dip>(?<dip>\d+\.\d+\.\d+\.\d+)|[^\"]+)?\".*userAgent=\"(?<useragent>.*?)\]
```
MSGDLV
```
MSGDLV.*?recipient=\"(?<login>(?<login>[^@]+)@(?<domainorigin>[^"]+)|[^\"]+)?\"\s+sender=\"(?<object>(?<object>(?<account>[^@]+)@(?<domain>[^\"]+))|[^\"]+)?\"\s+senderIP=\"(?<sip>(?<sip>\d+\.\d+\.\d+\.\d+)|[^\"]+)?\".*?threatsInfoMap="\[{(?:\\"[^"]+\":\\"[^"]+\",){5}\\\"threat\\\":\\\"(?<url>[^\\]+)\\.*?subject="(?<subject>[^"]+)".*?completelyRewritten="(?<command>[^"]+)\".*?messageParts=\"(?<vendorinfo>.*?md5\\":\\"(?<hash>[^\\]+)\\"[^\"]+\"filename\\\":\\\"(?<object>[^\\]+).*})\\]
```
Catch-all
```
^.*
```
