param(
    [Parameter(Mandatory=$true)]$basepath
    )

$EventLogNames = @("Application", "System")
$evtlogsummary = @() # create log summary
$addtlmaint = @() # Populate with additional maintenance types
# $basepath = "C:\temp"

# region additional maintenance functions
    function Start-ADMaintenance {
        param(
            [Parameter(Mandatory=$true)]$basepath
        )
        Invoke-Webrequest -Uri https://raw.githubusercontent.com/russelljt/servermaintenance/master/New-ADMaintenance.ps1 -OutFile $basepath\New-ADMaintenance.ps1
        Start-Sleep -Seconds 10
        powershell.exe -command "$basepath\New-ADMaintenance.ps1 -basepath $basepath"
    }

# endregion

    # Collect server hardware and OS licensing info
    function Get-HWInfo {
        param (
            $computername = $env:COMPUTERNAME,
            [string]$PSVer
        )

        if ($PSVer -ge "5") {
            [hashtable]$HWInfo = @{}
            $HWType = (Get-CimInstance -Class Win32_ComputerSystem -ComputerName $Computername | Select-Object Manufacturer,Model)
            $Serial = (Get-CimInstance -Class Win32_bios -ComputerName $Computername | Select-Object SerialNumber | Select-Object -ExpandProperty SerialNumber)
            $activation = (Get-CimInstance SoftwareLicensingProduct -ComputerName $env:computername -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" |  Where-Object licensestatus -eq 1  | Select-Object Name, Description)
            if ($activation) {$HWInfo.LicAct = "True"} else {$HWInfo.LicAct = "False"}
            if ($HWType.Model -like "*Virt*") {$VM = "True"} else { $VM = "False"}
            $HWInfo.VM = $VM
            $HWInfo.Serial = $Serial
            $HWInfo.LicName = $activation.Name
            $HWInfo.LicDesc = $activation.Description
            $HWInfo.Mfg = $HWType.Manufacturer
            $HWinfo.Model = $HWType.Model
        } else {
            [hashtable]$HWInfo = @{}
            $HWType = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computername | Select-Object Manufacturer,Model)
            $Serial = (Get-WmiObject -Class Win32_bios -ComputerName $Computername | Select-Object SerialNumber)
            $activation = (Get-WmiObject SoftwareLicensingProduct -ComputerName $env:computername -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" |  Where-Object licensestatus -eq 1  | Select-Object Name, Description)
            if ($activation) {$HWInfo.LicAct = "True"} else {$HWInfo.LicAct = "False"}
            if ($HWType.Model -like "*Virt*") {$VM = "True"} else { $VM = "False"}
            $HWInfo.VM = $VM
            $HWInfo.Serial = $Serial
            $HWInfo.LicName = $activation.Name
            $HWInfo.LicDesc = $activation.Description
            $HWInfo.Mfg = $HWType.Manufacturer
            $HWinfo.Model = $HWType.Model
        }
        return $HWInfo 
    }

    # Calculate Server uptime      
    Function Get-SrvUptime {
        param ([string]$ComputerName = $env:COMPUTERNAME,[string]$PSVer)
        if ($PSVer -ge "6") {
            $Uptime = Get-UpTime -Since
        } elseif ($PSVer -eq "5") {
            $Uptime = Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime | Select-Object -ExpandProperty LastBootUpTime
        } else {
            $System = Get-WmiObject win32_operatingsystem
            $Uptime =  $System.ConvertToDateTime($System.LastBootUpTime)
        }

        Write-Output ":::System uptime:::"
        Return $Uptime
    }

    # Collect Windows Roles currently installed
    function Get-Roles {
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/russelljt/servermaintenance/master/roles.txt -OutFile C:\temp\roles.txt
        $includedroles = Get-Content -Path C:\temp\roles.txt
        $roles = (($includedroles | ForEach-Object {[regex]::Escape($_)}) –join "|")
    
        $installedroles = Get-WindowsFeature | Where-Object {($_.InstallState -eq "Installed") -and ($_.name -match $roles)} | Select-Object Name
        
        # If roles are detected, start respective separate maintenance script
        Switch ($installedroles.name) {            
            "AD-Domain-Services" {$addtlmaint += "AD-Domain-Services"}
            # "FS-DFS-Replication" {}
            # "Hyper-V" {}
        }
        Write-Output ":::Installed Server Roles:::"
        return $installedroles | Format-Table -Autosize
    } 

    # Collect PowerShell version information
    Function Get-PSVersion {
        param (
            [string]$ComputerName = $env:COMPUTERNAME
        )
        [hashtable]$ReturnPSVer = @{}

        $PSVer = $psversiontable
        if ($PSVer.PSEdition) {
            $ReturnPSVer.PSEdition = $PSVer.PSEdition
        } else {
            $ReturnPSVer.PSEdition = "No Edition Listed"
        }

        $PSVerMaj = $PSVer.PSVersion.Major
        $ReturnPSVer.PSVersion = $PSVer.PSVersion
        $ReturnPSVer.PSMajorVersion = $PSVerMaj

        Return $ReturnPSVer
    }

    # Collect service information
    function Get-ServiceList { 
        $services = Get-Service
        # $os = (Get-CimInstance win32_operatingsystem -computername $Computer).Caption
        $runningsvc = $services | Where-Object {$_.Status -eq "running"}
        $stoppedsvc = $services | Where-Object {$_.Status -eq "stopped"}
        $autosvc = $services | Where-Object {$_.StartType -eq "automatic" -and $_.Status -eq "stopped"} | Select-Object @{Name='Service Name'; Expression={$_.DisplayName}}, Status
    
        Write-Output ":::Services Summary:::"
        Write-Output "Services Running:" $runningsvc.Count
        Write-Output "Services Stopped:" $stoppedsvc.Count
        Write-Output `n
        Write-Output "Automatic Services Not Running:"
        $autosvc | Format-Table
    }

    # Collect services running as service accounts
    function Get-ServiceAccounts {
        $svcaccts = Get-CIMInstance  -Class Win32_Service | `
            Where-Object {($null -ne $_.StartName -and $_.StartName -ne "LocalSystem" -and $_.StartName -notlike "NT AUTHORITY*" )} | `
            Select-Object DisplayName,Name,StartMode,StartName
        Write-Output ":::Services using Service Accounts:::"
        return $svcaccts
    }

    # Collect data on local disks
    function Get-DiskInfo {
        param ([string]$ComputerName = $env:COMPUTERNAME,[string]$PSVer,[string]$IsVirt)
        if (($PSVer -ge "5") -and ($IsVirt -eq "True") ) {
            $Volume = Get-CimInstance -ComputerName $computerName Win32_Volume | Where-Object {$_.DriveType -eq 3 -and $Null -ne $_.DriveLetter}  
            [hashtable]$DiskFrag = @{}
            $DiskFrag.DefragRecommended = "Virt-Skipping" 
            $DiskInfo = Get-CimInstance -ComputerName $computerName Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object Name, @{n='Size (GB)';e={"{0:n2}" -f ($_.size/1gb)}}, @{n='FreeSpace (GB)';e={"{0:n2}" -f ($_.freespace/1gb)}}, @{n='PercentFree';e={"{0:n2}" -f ($_.freespace/$_.size*100)}}, @{n="Defrag Recommended?";e={"{0:n2}" -f $DiskFrag.DefragRecommended}}    
        } elseif (($PSVer -ge "5") -and ($IsVirt -eq "False") ) { 
            $Volume = Get-CimInstance -ComputerName $computerName Win32_Volume | Where-Object {$_.DriveType -eq 3 -and $Null -ne $_.DriveLetter}  
            $DiskFrag = ( $Volume | Invoke-CimMethod -MethodName defraganalysis -Arguments @{defraganalysis=$volume} | Select-Object -property DefragRecommended, ReturnValue ) 
            $DiskInfo = Get-CimInstance -ComputerName $computerName Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object Name, @{n='Size (GB)';e={"{0:n2}" -f ($_.size/1gb)}}, @{n='FreeSpace (GB)';e={"{0:n2}" -f ($_.freespace/1gb)}}, @{n='PercentFree';e={"{0:n2}" -f ($_.freespace/$_.size*100)}}, @{n="Defrag Recommended?";e={"{0:n2}" -f $DiskFrag.DefragRecommended}}    
        } elseif (($PSVer -lt "5") -and ($IsVirt -eq "False") ) {
            $Volume = Get-WmiObject -ComputerName $computerName Win32_Volume | Where-Object {$_.DriveType -eq 3 -and $Null -ne $_.DriveLetter}  
            $DiskFrag = $Volume.DefragAnalysis().DefragAnalysis
            $DiskInfo = Get-WmiObject -ComputerName $computerName Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object Name, @{n='Size (GB)';e={"{0:n2}" -f ($_.size/1gb)}}, @{n='FreeSpace (GB)';e={"{0:n2}" -f ($_.freespace/1gb)}}, @{n='PercentFree';e={"{0:n2}" -f ($_.freespace/$_.size*100)}}, @{n="Fragmentation";e={"{0:n2}" -f $DiskFrag.TotalPercentFragmentation}}
        } elseif (($PSVer -lt "5") -and ($IsVirt -eq "True") ) {
            $Volume = Get-WmiObject -ComputerName $computerName Win32_Volume | Where-Object {$_.DriveType -eq 3 -and $Null -ne $_.DriveLetter}  
            [hashtable]$DiskFrag = @{}
            $DiskFrag.TotalPercentFragmentation = "Virt-Skipping" 
            $DiskInfo = Get-WmiObject -ComputerName $computerName Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object Name, @{n='Size (GB)';e={"{0:n2}" -f ($_.size/1gb)}}, @{n='FreeSpace (GB)';e={"{0:n2}" -f ($_.freespace/1gb)}}, @{n='PercentFree';e={"{0:n2}" -f ($_.freespace/$_.size*100)}}, @{n="Fragmentation";e={"{0:n2}" -f $DiskFrag.TotalPercentFragmentation}}
        }
        Write-Output ":::Disk information:::"
        return $DiskInfo
    }

    # Collect IP and MAC addresses from enabled netadapters
    function Get-NetInfo{ 
        param (
            $computername = $env:COMPUTERNAME
        )

        $netadapters = ( Get-CimInstance -class "Win32_NetworkAdapterConfiguration" -computername $computername | Where-Object {$_.IPEnabled -Match "True"} )
        foreach ($netadapter in $netadapters) {  
            $netadapter | Select-Object -Property Description,MacAddress,IPAddress | Format-Table -AutoSize
        }  
    }

    # Collect network port information
    function Get-NetPortInfo{
        param (
            $computername = $env:COMPUTERNAME,[string]$PSVer
        )

        if ($PSVer -ge "5") {
            $established = (Get-NetTCPConnection -State Established | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{name='Process';expression={(Get-Process -Id $_.OwningProcess).Name}}, CreationTime | Sort-Object Process | Format-Table -AutoSize)
            $listening = (Get-NetTCPConnection -State Listen | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{name='Process';expression={(Get-Process -Id $_.OwningProcess).Name}}, CreationTime | Sort-Object Process | Format-Table -AutoSize)
            $openports = (Get-NetTCPConnection -State Listen | Select-Object LocalPort | Sort-Object -Property LocalPort -Unique | Format-Table -HideTableHeaders)
            [hashtable]$netportinfo = @{}
            $netportinfo.established = $established
            $netportinfo.listening = $listening
            $netportinfo.openports = $openports
        } else {
            $netportinfo = "Not Yet Supported (PSVer: $psver)"
        }
        return $netportinfo
    }

    # Collect NTP servers
    Function Get-NTPConfig {
        $ntp = w32tm /query /status
        return $ntp
    }

    # Collect scheduled tasks and run info
    Function Get-SchTasks {
        $schtasks = @(Get-ScheduledTask -TaskPath \ | Get-ScheduledTaskInfo )
        $schtaskstatus = @()
        foreach ($task in $schtasks) { 
            switch ($task.LastTaskResult) {
                "0" {$taskstatus = "Operation Completed Successfully"}
                "267011" {$taskstatus = "Task has not yet run"}
                default {$taskstatus = "Unknown code"}
            }
            $st = [ordered]@{}
            $st.'Name' = $task.TaskName.SubString(0, [Math]::Min($task.TaskName.Length, 20))
            $st.'Last Run' = $task.LastRunTime
            $st.'Last Result' = $taskstatus
            $st.'Missed Runs' = $task.NumberOfMissedRuns
            $st.'Next Run' = $task.NextRunTime
            $SchtaskStatus += New-Object -TypeName PSObject -Property $st
        }
        $schtaskstatusall = $schtaskstatus | Sort-Object -Property Name | Format-Table -AutoSize
        Write-Output ":::Scheduled Task information:::"
        return $schtaskstatusall
    }

    # Collect log information from classic Application and System logs
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

    # Collect failures from classic Security log
    function Get-FailedLogons {
        function Get-FailureReason {
            Param($FailureReason)
              switch ($FailureReason) {
                '0xC0000064' {"Account does not exist"; break;}
                '0xC000006A' {"Incorrect password"; break;}
                '0xC000006D' {"Incorrect username or password"; break;}
                '0xC000006E' {"Account restriction"; break;}
                '0xC000006F' {"Invalid logon hours"; break;}
                '0xC000015B' {"Logon type not granted"; break;}
                '0xc0000070' {"Invalid Workstation"; break;}
                '0xC0000071' {"Password expired"; break;}
                '0xC0000072' {"Account disabled"; break;}
                '0xC0000133' {"Time difference at DC"; break;}
                '0xC0000193' {"Account expired"; break;}
                '0xC0000224' {"Password must change"; break;}
                '0xC0000234' {"Account locked out"; break;}
                '0x0' {"0x0"; break;}
                default {"Other"; break;}
            }
          }
        
        #check failed logins
        $startdate = (Get-Date).AddDays(-30)       
        $failedlogons = Get-WinEvent -FilterHashtable @{ LogName="Security"; ID=4625; StartTime=$startdate }
        $failedlogonstatus = @()
    
        foreach ($failedlogon in $failedlogons) {
            [hashtable]$fl = @{}
           
            $msgstring = $failedlogon.Message
            $sourceaddr = (($msgstring).Split("`n") | Select-String -Pattern "(?<SourceAddr>^\s+Source Network Address:\s+(.+))").ToString().Replace("`tSource Network Address:`t","").Trim()
            $acctnamearr = ($msgstring).Split("`n") | Select-String -Pattern "(?<AcctName>^\s+Account Name:\s+(.+))"
            $fail1 = (($msgstring).Split("`n") | Select-String -Pattern "(?<AcctName>^\s+Status:\s+(.+))").ToString().Replace("`tStatus:`t","").Trim()
            $fail2 = (($msgstring).Split("`n") | Select-String -Pattern "(?<AcctName>^\s+Sub Status:\s+(.+))").ToString().Replace("`tSub Status:`t","").Trim()
            $facctname1,$facctname2 = $acctnamearr
            $acct1 = ($facctname1.ToString()).Replace("`tAccount Name:`t`t","").Trim()
            $acct2 = ($facctname2.ToString()).Replace("`tAccount Name:`t`t","").Trim()
            if ($acctname -like "*-*") { $acctname = "LocalAcct: $acct1"} else { $acctname = $acct2}
            if ($sourceaddr -like "*-*") {$sourceaddr = "localhost"}
    
            $fl.SourceAddr = $sourceaddr
            $fl.AcctName = $acctname
            $fl.Time = $failedlogon.TimeCreated
            $fl.FailStatus = Get-FailureReason -failurereason $fail1
            $fl.FailSubStatus = Get-FailureReason -failurereason $fail2
            
            $FailedLogonStatus += New-Object -TypeName PSObject -Property $fl 
            $failuresumm = $FailedLogonStatus | Format-Table -AutoSize
    
        } 

        if ($failedlogons.count -gt 0){
            return $failuresumm
        } else {
            Write-Output "No logon failures found"
        }    
    }

    # Execute maintenance data gathering functions and prepare report
    function Start-Maintenance{
        [Cmdletbinding()]
        param(
            $basepath
        )
        
        $date = Get-Date -Format "MMddyyyy"
        $maintpath = "$basepath\maint"
        $maintfile = "maint_report-$env:COMPUTERNAME-"+$date+".log"
        # $maintallfile = "maint_all-$env:COMPUTERNAME-"+$date+".log"
        $maintlog = "$maintpath\$maintfile"

        if (!(Test-Path $maintpath)) {
            New-Item -ItemType Directory -Path $maintpath
        }

        $PSVerSummary = Get-PSVersion
        # $PSInfoVer = $PSVerSummary.PSVersion.ToString()
        # $PSInfoEd = $PSVerSummary.PSEdition.ToString()
        $PSMaj = $PSVerSummary.PSMajorVersion.ToString()

        # Create report components
        $hwinfo = Get-HWInfo -PSVer $PSMaj
        $isVirt = $hwinfo.vm
        $lastboot = Get-SrvUptime -PSVer $PSMaj
            
        $events = Get-EvtLogsSummary
        $fails = Get-FailedLogons
        $ntpsum = Get-NTPConfig
        $svclist = Get-ServiceList
        $svcaccts = Get-ServiceAccounts
        $instroles = Get-Roles
        $tasks = Get-SchTasks
        $DiskSummary = Get-DiskInfo -PSVer $PSMaj -IsVirt $isVirt
        $netinfo = Get-NetInfo
        $NetPortInfo = Get-NetPortInfo -PSVer $PSMaj
        $netopenports = $netportinfo.openports
        $netlistening = $netportinfo.listening
        $netestablished = $netportinfo.established
    
        $(
            # Build final report
            Write-Output "******Maintenance Report******"
            Write-Output "Current Date: $date"
            $hwinfo | Format-Table -AutoSize
            $lastboot
            $DiskSummary | Format-Table -AutoSize
            Write-Output `n
            $instroles
            $svclist
            $svcaccts
            $tasks
            Write-Output ":::Network adapter information:::"
            $netinfo
            Write-Output ":::Established network ports:::"
            $netestablished
            Write-Output ":::Listening network ports:::"
            $netlistening
            Write-Output ":::Open network ports:::"
            $netopenports
            Write-Output ":::NTP server:::"
            $ntpsum
            Write-Output ":::Event Log Summary - past 30 days:::"
            $events
            Write-Output ":::Login failures - past 30 days:::"
            $fails
            Write-Output `n
            Write-Output ("######################### Maintenance Report Complete #########################")

        ) *>&1 >> $maintlog

    }

    Start-Maintenance -basepath $basepath