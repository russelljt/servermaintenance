function Get-EvtLogsSummary {
    $startdate = (Get-Date).AddDays(-30)
    
    foreach ($EventLog in $EventLogNames) {
        $reviewlog = Get-WinEvent -FilterHashtable @{ LogName=$EventLog; Level=1,2,3; StartTime=$startdate }
        $logsum = $reviewlog | Sort-Object -Property Id -Unique -Descending #| sort-object -Property ID -Descending
        $idcounts = $reviewlog | Group-Object -Property ID | Sort-Object -Property Count -Descending | Select-Object Count,Name | Format-Table
        Write-Output "::$EventLog Event Log::"
        $evtlogsummary += $idcounts
        $evtlogsummary += $logsum        
        }
    return $evtlogsummary
    }