function Get-Roles {
    $includedroles = Get-Content -Path $psscriptpath\roles.txt
    $roles = (($includedroles | ForEach-Object {[regex]::Escape($_)}) –join "|")
    
    Get-WindowsFeature | Where-Object {($_.InstallState -eq "Installed") -and ($_.name -match $roles)} 
} 

