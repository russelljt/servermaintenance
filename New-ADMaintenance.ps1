param(
    [Parameter()]$basepath
    )
    
$EventLogNames = @("DFS Replication", "Directory Service", "DNS Server")
$evtlogsummary = @() # create log summary

function Get-ADDSInfo {
    # Collect Forest-level information
    $adforest = Get-ADForest
    $partitions = Get-ADForest | Select-Object -ExpandProperty ApplicationPartitions
    $forestdnspart = $partitions[1]
    $forestdns = "LDAP://CN=Infrastructure,$forestdnspart"
    
    Write-Output "Active Directory Forest configuration"
    $adforest | Select-Object Name,ForestMode,RootDomain,SchemaMaster,DomainNamingMaster | Format-List
    Write-Output "Forest DNS Zone Master"
    [adsi]$forestdns | Select-Object -ExpandProperty fsmoRoleOwner | Format-List
    Write-Output `n
    Write-Output "UPN Suffixes"
    $adforest | Select-Object -ExpandProperty UPNSuffixes | Format-List
    Write-Output `n
    Write-Output "Active Directory Recycle Bin configuration"
    Get-ADOptionalFeature -Identity "Recycle Bin Feature" | Select-Object 
    Write-Output `n
    Write-Output "All trusted domains"
    Get-ADTrust -Filter * 

    # Collect Domain-level information
    $domains = Get-ADForest | Select-Object -ExpandProperty Domains
    foreach ($domain in $domains){
        $dn = Get-ADDomain -Identity $domain | Select-Object -ExpandProperty DistinguishedName
        Write-Output "Domain information: $domain"
        Get-ADDomain -Identity $domain | Select-Object DistinguishedName,NetBIOSName,DomainMode,PDCEmulator,RIDMaster,InfrastructureMaster
        Write-Output `n
        Write-Output "Domain Controllers"
        Get-ADDomainController -Discover -DomainName $domain | Select-Object -ExpandProperty HostName
        Write-Output `n
        Write-Output "Subordinate references"
        Get-ADDomain -Identity $domain | Select-Object -ExpandProperty SubordinateReferences
        Write-Output `n
        Write-Output "Domain DNS Zone Master"
        $domaindns = "LDAP://CN=Infrastructure,DC=DomainDnsZones,$dn"
        [adsi]$domaindns | Select-Object -ExpandProperty fsmoRoleOwner | Format-List *
    }

    # Collect site replication subnets
    Write-Output `n
    Write-Output "AD Replication Sites and Subnets"
    Get-AdReplicationSubnet -Filter * | Select-Object Site,Name | Sort-Object Site | Format-Table -AutoSize
    Write-Output `n
    Write-Output "AD Replication Connections"
    Get-ADReplicationConnection -Filter * | Select-Object ReplicateFromDirectoryServer,ReplicateToDirectoryServer,AutoGenerated | Sort-Object ReplicateFromDirectoryServer | Format-Table -AutoSize
}

function Get-DCdiag {
    # Run dcdiag and collect errors
    $dcdiag = dcdiag /q
    if (!($dcdiag)) { $dcdiag = "no errors to report" }
    Return $dcdiag
}

function Get-FRSState {
    $frsstate = dfsrmig /getmigrationstate
    if ($frsstate -like "*Eliminated*") { 
        $dfsrstate = "Sysvol is using DFSR"
    } elseif ($frsstate -like "*Prepared*") { 
        $dfsrstate = "Sysvol is using FRS *** (DFSR Mig Status - Prepared)"
    } elseif ($frsstate -like "*Redirected*") { 
        $dfsrstate = "Sysvol is using FRS *** (DFSR Mig Status - Redirected)"
    } else { 
        $dfsrstate = "Sysvol is using FRS ***" 
    }
    Return $dfsrstate
}

function Get-ReplStatus {
    $repstatus = @{}
    $repsum = repadmin /replsummary
    $repqueue = repadmin /queue
    $showrepl = repadmin /showrepl
    $repstatus.repsum = $repsum.Trim()
    $repstatus.queue = $repqueue.Trim()
    $repstatus.showrepl = $showrepl.Trim()
    Return $repstatus
}

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

function Start-ADMaintenance{
    [Cmdletbinding()]
    param([string]$Computername,
    $basepath
    )

    Import-Module ActiveDirectory
    $date = Get-Date
    $maintpath = "$basepath\maint"
    $maintfile = "maint_report-AD-$env:USERDOMAIN-"+(Get-Date -Format "MMddyyyy")+".log"
    $maintlog = "$maintpath\$maintfile"

    if (Test-Path $maintpath) { 
        Write-Verbose "($maintpath) already exists" -Verbose 
    } else { 
        New-Item -ItemType Directory -Path $maintpath -Force
        Write-Verbose "($maintpath) was created" -Verbose 
    }

    $(
        $forestinfo = Get-ADDSInfo
        $dcdiag = Get-DCDiag
        $frsstate = Get-FRSState
        $replstatus = Get-ReplStatus
        $events = Get-EvtLogsSummary

        Write-Output "******AD Maintenance Report******"
        Write-Output "Current Date: $date"
        Write-Output "*** Forest / Domains info ***"
        $forestinfo
        Write-Output `n
        Write-Output "*** DCDiag ***"
        $dcdiag
        Write-Output `n
        Write-Output "*** FRS Status ***"
        $frsstate
        Write-Output `n
        Write-Output "*** Replication Status ***"
        $replstatus.repsum
        Write-Output `n
        Write-Output "*** Event Logs ***"
        $events

    ) *>&1 >> $maintlog
    
}

Start-ADMaintenance -basepath $basepath