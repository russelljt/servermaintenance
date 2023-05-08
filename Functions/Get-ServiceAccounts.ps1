
function Get-ServiceAccounts {
    $svcaccts = Get-CIMInstance  -Class Win32_Service | `
        Where-Object {($null -ne $_.StartName -and $_.StartName -ne "LocalSystem" -and $_.StartName -notlike "NT AUTHORITY*" )} | `
        Select-Object DisplayName,Name,StartMode,StartName
        
    return $svcaccts
}