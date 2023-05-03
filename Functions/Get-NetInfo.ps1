function Get-NetInfo{ 
    param ($computername = $env:COMPUTERNAME) 
    $netadapters = ( Get-CimInstance -class "Win32_NetworkAdapterConfiguration" -computername $computername | Where-Object {$_.IPEnabled -Match "True"} )
    foreach ($netadapter in $netadapters) {  
        $netadapter | Select-Object -Property Description,MacAddress,IPAddress 
    }  
}