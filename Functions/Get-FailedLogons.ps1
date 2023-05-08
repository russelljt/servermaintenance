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