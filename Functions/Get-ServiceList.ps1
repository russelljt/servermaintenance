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