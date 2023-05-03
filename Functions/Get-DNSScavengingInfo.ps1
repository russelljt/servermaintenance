function Get-DNSScavengingInfo {
    Write-Output "DNS Server Scavenging"
    Get-DnsServerScavenging

    Write-Output "DNS Zone Aging Settings"
    $zones = (Get-DnsServerZone | Where-Object {($_.ZoneName -NotLike '*arpa*') -and ($_.ZoneName -NE 'TrustAnchors') -and ($_.ZoneType -eq "Primary")}).ZoneName
    foreach ($zone in $zones){
        Get-DnsServerZoneAging -Name $zone
    }
}

Get-DNSScavengingInfo