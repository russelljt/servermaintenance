$EventLogNames = '' # "Application", "System", "DFS Replication", "Directory Service", "DNS Server"
$evtlogsummary = @() # create log summary

function Get-EvtLogsSummary {

    foreach ($EventLog in $EventLogNames) {
        $reviewlog = Get-WinEvent -LogName $EventLog -FilterXPath "*[System[(Level=1 or Level=2 or Level=3)]]"
        $logsum = $reviewlog | Sort-Object -Property Id -Unique -Descending #| sort-object -Property ID -Descending
        $idcounts = $reviewlog | Group-Object -Property ID | Sort-Object -Property Count -Descending | Select-Object Count,Name | Format-Table

        $evtlogsummary += $logsum
        $evtlogsummary += $idcounts
        }
    }

