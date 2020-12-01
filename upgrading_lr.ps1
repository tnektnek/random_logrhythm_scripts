# Can be further developed to kick off specific executables, but this is to specifically make upgrading the LR deployment faster
# Database upgrade tool stops all LR services and this is inevitable to kill all connections to the DB to be able to execute its upgrade scripts
## Service Registry running can specifically hang the database upgrade scripts
# LR Install specifically needs Elasticsearch to be green, service registry to be running for LRII, and scsm should always be running to accept syslog feed to spool local on disk

$svc = @("lr-elasticsearch","LogRhythmServiceRegistry", "scsm")
get-service -displayname logrhythm* | ? { $_.Status -eq 'Running' } | ? {$svc -notcontains $_.Name} | % { Stop-Service $_}
