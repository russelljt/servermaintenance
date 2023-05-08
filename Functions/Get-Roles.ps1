function Get-Roles {
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/russelljt/servermaintenance/master/roles.txt -OutFile C:\temp\roles.txt
    $includedroles = Get-Content -Path C:\temp\roles.txt
    $roles = (($includedroles | ForEach-Object {[regex]::Escape($_)}) –join "|")

    $installedroles = Get-WindowsFeature | Where-Object {($_.InstallState -eq "Installed") -and ($_.name -match $roles)} | Select-Object Name
    
    <#
    Switch ($installedroles.name) {
        # If roles are detected, start respective separate maintenance script
        "AD-Domain-Services" {}
        "FS-DFS-Replication" {}
        "Hyper-V" {}
    }
    #>
    return $installedroles
} 

