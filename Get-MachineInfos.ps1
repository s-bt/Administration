<#
.DESCRIPTION
Get service, scheduled tasks and IIS application pools that run with a specific user
Get members of the local administrator group (RID 544)
Get the firewall status
Get the operating system
Get TCP listening connections and also show the process names and corresponding service displayname
Get UDPconnections and also show the process names and corresponding service displayname
Write the output into a CLIXML file for later reporting
PARTS OF THIS SCRIPT ARE MODIFIED FOR GERMAN OS ONLY, SO YOU MIGHT NEED TO ADAPT IT

.AUTHOR
Sebastian Bammer-Tasch
Parts of the script are borrowed from 'Get-Dependencies.ps1'
#>

Write-Host "Start"
$outHT = @{'WindowsServices'=$null;'IISApplicationPools'=$null;'ScheduleTasks'=$null;'LocalAdmins'=$null;'TCPListeners'=$null;'UDPListeners'=$null}
$NetBiosDomainName = "MyDomainNetBiosName"
$Generaloutcol = New-Object System.Collections.ArrayList
$SERVERNAME = "SERVER1"
#region Windows Services

Write-Host "Checking Windows services"
$WindowsServices = Get-WmiObject -class win32_service | where { $_.StartName -ne $null -and $_.StartName.ToLower() -NotLike 'NT AUTHORITY\SYSTEM' -and $_.StartName.ToLower() -NotLike 'NT-AUTORITÄT\Lokaler Dienst' -and $_.StartName.ToLower() -NotLike 'NT-AUTORITÄT\Netzwerkdienst' -and $_.StartName.ToLower() -NotLike 'nt authority\*' -and $_.StartName.ToLower() -NotLike 'nt service\*' -and $_.StartName.ToLower() -ne 'localsystem' -and $_.StartName.ToLower() -ne 'local service' -and $_.StartName.ToLower() -ne 'local system' -and $_.StartName.ToLower() -ne 'networkservice' -and $_.StartName.ToLower() -ne 'system' -and $_.StartName.ToLower() -ne '\' -and $_.StartName.ToLower() -ne ''} | select DisplayName, StartName
if (@($WindowsServices).count -gt 0) {
    $outCol = New-Object System.Collections.ArrayList
    foreach ($WindowsService in $WindowsServices) {
        #if ($WindowsService.StartName -ne $null -and $WindowsService.StartName.ToString().EndsWith("$") -ne $true) {
        if ($WindowsService.StartName -ne $null) {
            $outObj = New-Object -TypeName PSObject -Property @{DisplayName=$WindowsService.displayname;StartName=$WindowsService.StartName}
            $outObjNew = New-Object -TypeName PSObject -Property @{DisplayName=$WindowsService.displayname;Username=$WindowsService.StartName;type="Service";Computername=$env:COMPUTERNAME}
            [void]$Generaloutcol.Add($outObjNew)
            [void]$outCol.Add($outObj)
        }
    }
    $outHT.'WindowsServices'=$outCol
}
#endregion Windows Services
#region IIS
Write-Host "Checking IIS application pools"
$IISVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\InetStp\Components\" -Name "CoreWebEngine" -ErrorAction SilentlyContinue
If (($IISVersion -ne $null) -and ($IISVersion.Length -ne 0)) {
    #Import-Module WebAdministration
    if ([System.Version] (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion -ge [System.Version] "6.1") {
        Import-Module WebAdministration  #IIS7.5 and above
    }
    else {
        Add-PSSnapin WebAdministration #IIS 7.0
    }
    $webapps = Get-WebApplication
    foreach ($webapp in get-childitem IIS:\AppPools\) {
        $outCol = New-Object System.Collections.ArrayList
        $name = "IIS:\AppPools\" + $webapp.name
        if ($webapp.processModel.userName.ToString() -ne '' -and $webapp.processModel.userName.ToString().EndsWith("$") -ne $true -and $webapp.processModel.userName.ToString() -ne '\') {
            $FoundIISInterestingAppPool = $true
            $outObj = New-Object -TypeName PSObject -Property @{WebAppName=$webapp.name;Username=$webapp.processModel.userName}
            $outObjNew = New-Object -TypeName PSObject -Property @{DisplayName=$webapp.name;Username=$webapp.processModel.userName;type="IISAppPool";Computername=$env:COMPUTERNAME}
            [void]$outCol.Add($outObj)
            [void]$Generaloutcol.Add($outObjNew)
        }
    }
    if ($FoundIISInterestingAppPool -eq $true) {
        $outHT.'IISApplicationPools'=$outCol
    }
}
#endregion IIS
#region Scheduled Tasks
Write-Host "Checking scheduled tasks"
$schtask = schtasks.exe /query /V /FO CSV | ConvertFrom-Csv
if ($schtask) {
    $EOP = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $UninterestingUsers = @('NT AUTHORITY\SYSTEM','NT-AUTORITÄT\Lokaler Dienst','NT-AUTORITÄT\Netzwerkdienst','system','s-1-5-18','n/a','users','everyone','local service','interactive','network service','administrators','authenticated users','nt authority\system','\everyone','everyone','nt authority\local service','nt authority\interactive','builtin\users','nt authority\network service','nt authority\authenticated users' ,'builtin\administrators','jeder','lokaler dienst','interaktiv','netzwerkdienst','administratoren','authentifizierte benutzer','\jeder','nt authoritt\lokaler dienst','nt authorität\lokaler dienst','nt authoritt\interaktiv','nt authorität\interaktiv','vordefiniert\benutzer','benutzer','nt authoritt\netzwerkdienst','nt authorität\netzwerkdienst','nt authoritt\authentifizierte benutzer','nt authorität\authentifizierte benutzer','vordefiniert\administratoren','administratoren','NT AUTHORITY\SYSTEM','')
    foreach ($sch in $schtask) {
        # This is required for german OS
        $p = $sch.psobject.Properties | ?{$_.name -like '*Als Benutzer aus*'}
        #If (($sch."Logon Mode" -eq 'Interactive/Background' -and $sch."Run As User" -ne '' -and $sch."Run As User" -notin $UninterestingUsers -and $sch."Run As User" -notlike '*stop on battery mode*') -or ($sch.Anmeldemodus -eq 'Interaktiv/Hintergrund' -and $sch.psobject.Properties[$p.Name].value -ne '' -and $sch.psobject.Properties[$p.Name].value -notlike '*stop on battery mode*' -and $sch.psobject.Properties[$p.Name].value -notin $UninterestingUsers)) {
        try {
            #If (($sch."Run As User" -ne '' -and $sch."Run As User" -notin $UninterestingUsers) -or ($sch.psobject.Properties[$p.Name].value -ne '' -and $sch.psobject.Properties[$p.Name].value -notin $UninterestingUsers)) {
            If ($true) {
                $outCol = New-Object System.Collections.ArrayList						
                    $outObj = New-Object -TypeName PSObject -Property @{TaskName=$null;Username=$null} -ErrorAction SilentlyContinue
                    $outObjNew = New-Object -TypeName PSObject -Property @{DisplayName=$null;Username=$null;type="ScheduledTask";Computername=$env:COMPUTERNAME}
                    try {
                        $outobj.TaskName=$sch.TaskName.TrimStart('\')
                        $outObjNew.DisplayName = $sch.TaskName.TrimStart('\')
                    } catch {
                        try {
                            $outobj.TaskName=$sch.Aufgabenname.TrimStart('\')
                            $outObjNew.DisplayName = $sch.Aufgabenname.TrimStart('\')
                        } catch {}
                    }
                
                    if ($sch."Run As User" -ne $null) {
                        $UserName = $sch."Run As User"
                    } elseif ($sch.psobject.Properties[$p.name].Value -ne $null) {
                        $UserName = $sch.psobject.Properties[$p.name].Value
                    }
                    #We first need to check if the Username has a slash in it, so we know whether to check the XML file as well - Windows Server 2016 and Windows 10 bug
                    if ($UserName -like '*\*') {
                        $outObj.Username = $UserName
                        $outObjNew.Username = $UserName
                    }
                    else {
                        #If schtasks.exe is not reporting the domain or host details for the account, we will also check the XML file
                        $xml = [xml] (get-content "$env:windir\System32\Tasks\$($outObj.TaskName)")
                        $UserName = $xml.Task.Principals.Principal.UserId
                        if ($UserName -ne 'S-1-5-18') { #Imported scheduled tasks via xml files can report this value instead of SYSTEM
                            $outObj.UserName = $UserName
                            $outObjNew.Username = $UserName
                        }
                    }
                if ($UserName -like "*$NetBiosDomainName*") {
                    [void]$Generaloutcol.Add($outObjNew)
                    [void]$outCol.Add($outObj)	
                }
            }
        } catch {
            Write-Host "Error checking task" -ForegroundColor Red
        }
    }
    $ErrorActionPreference = $E
    $outHT.'ScheduleTasks'=$outCol
}
#endregion Scheduled Tasks
#region LocalAdmins
Write-Host "Checking Local Admins"
$OutCol = New-Object System.Collections.ArrayList

try {
    Foreach ($i in (Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)) {
        $outObj = New-Object -TypeName PSObject -Property @{Name=$i.Name;objectClass=$i.ObjectClass}
        $outObjNew = New-Object -TypeName PSObject -Property @{DisplayName=$i.Name;Username=$i.Name;type="LocalAdmins";Computername=$env:COMPUTERNAME}
        [void]$OutCol.Add($outObj)
    }
} catch {}

#Foreach ($i in @(net.exe localgroup administrators | ?{$_ -like "*$NetBiosDomainName*" -and $_ -ne "$NetBiosDomainName\Domänen-Admins" -and $_ -notmatch "(T|Tier).*"})) {
Foreach ($i in @(net.exe localgroup administrators) |?{$_ -notmatch "^(\s|\t|-|Der Befehl|Mitglieder|Aliasname|Beschreibung).*" -and ($_.Length -ne 0)}) {
    $outObjNew = New-Object -TypeName PSObject -Property @{DisplayName=$i;Username=$i;type="LocalAdmins";Computername=$env:COMPUTERNAME}
    [void]$Generaloutcol.Add($outObjNew)
}

#Foreach ($i in @(net.exe localgroup administratoren | ?{$_ -like "*$NetBiosDomainName*" -and $_ -ne "$NetBiosDomainName\Domänen-Admins" -and $_ -notmatch "(T|Tier).*"})) {
Foreach ($i in @(net.exe localgroup administratoren) |?{$_ -notmatch "^(\s|\t|-|Der Befehl|Mitglieder|Aliasname|Beschreibung).*" -and ($_.Length -ne 0)}) {
    $outObjNew = New-Object -TypeName PSObject -Property @{DisplayName=$i;Username=$i;type="LocalAdmins";Computername=$env:COMPUTERNAME}
    [void]$Generaloutcol.Add($outObjNew)
}

$outHT.LocalAdmins = $OutCol
#endregion LocalAdmins

#region firewall status
Write-Host "Checking Firewall status"
$outObjNew = New-Object -TypeName PSObject -Property @{DisplayName=((netsh advfirewall show domain  | sls status).ToString().Replace('Status','').Replace(" ",""));Username="$NetBiosDomainName\$($env:COMPUTERNAME)";type="Firewallstatus";Computername=$env:COMPUTERNAME}
[void]$Generaloutcol.Add($outObjNew)
#endregion firewall status


#region os
Write-Host "Checking Operating System"
$outObjNew = New-Object -TypeName PSObject -Property @{Username=$env:COMPUTERNAME;type="OS";displayname=(Get-WmiObject Win32_Operatingsystem -Property caption).caption;Computername=$env:COMPUTERNAME}
[void]$Generaloutcol.Add($outObjNew)
#endregion os


#region network tcp listeners
Write-Host "Checking TCP listeners"
$TCPListening = Get-NetTCPConnection -State Listen | ?{$_.LocalAddress -notmatch "127\.0\.0\..|::"}
Foreach ($process in $TCPListening) {
    $Process | Add-Member -MemberType NoteProperty -Name OwningProcessName -Value (Get-process -Id $process.OwningProcess).ProcessName
    $Process | Add-Member -MemberType NoteProperty -Name OwningProcessPath -Value (Get-process -Id $process.OwningProcess).Path
    
    # If the PID corresponds to multiple services (e.g. LSASS), then we will return "MultipleServices", otherwise the service displayname
    $OwningProcessWin32Service = @(Get-WmiObject -Query "SELECT DisplayName FROM Win32_Service WHERE ProcessId='$($process.OwningProcess)'")
    
    If ($OwningProcessWin32Service.Count -gt 1) {
        $Process | Add-Member -MemberType NoteProperty -Name OwningProcessServiceDisplayName -Value ($OwningProcessWin32Service.DisplayName -join ':')
    }
    If ($OwningProcessWin32Service.Count -eq $null) {
        $Process | Add-Member -MemberType NoteProperty -Name OwningProcessServiceDisplayName -Value $null
    }
    If ($OwningProcessWin32Service.Count -eq 1) {
        $Process | Add-Member -MemberType NoteProperty -Name OwningProcessServiceDisplayName -Value $OwningProcessWin32Service[0].DisplayName
    }


    $outObjNew = New-Object -TypeName PSObject -Property @{Username=$env:COMPUTERNAME;type="TCPListener";displayname="$($process.LocalAddress):$($process.LocalPort):$($process.OwningProcessName):$($process.OwningProcessServiceDisplayName)";Computername=$env:COMPUTERNAME}
    [void]$Generaloutcol.Add($outObjNew)
}
$outHT.TCPListeners = ($TCPListening | select LocalAddress,LocalPort,OwningProcessName,OwningProcessPath,OwningProcessServiceDisplayName)

#endregion network tcp listeners

#region network UDP listeners
Write-Host "Checking UDP endpoints"
$UDPListening = Get-NetUDPEndpoint | ?{$_.LocalAddress -notmatch "127\.0\.0\..|::"}
$HTProcsAlreadyProcessed = @{}

Foreach ($process in $UDPListening) {
    #region filter
    # As there might be thousands of UDP endpoints, we will only process connections with the same owning process once.
    # as this is all we require.
    if ($process.OwningProcess -in $HTProcsAlreadyProcessed.keys){
        continue
    }

    $EAP = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $HTProcsAlreadyProcessed.Add($process.OwningProcess,$null)
    $ErrorActionPreference = $EAP
    #endregion filter

    $Process | Add-Member -MemberType NoteProperty -Name OwningProcessName -Value (Get-process -Id $process.OwningProcess).ProcessName
    $Process | Add-Member -MemberType NoteProperty -Name OwningProcessPath -Value (Get-process -Id $process.OwningProcess).Path
    
    # If the PID corresponds to multiple services (e.g. LSASS), then we will return "MultipleServices", otherwise the service displayname
    $OwningProcessWin32Service = @(Get-WmiObject -Query "SELECT DisplayName FROM Win32_Service WHERE ProcessId='$($process.OwningProcess)'")
    
    If ($OwningProcessWin32Service.Count -gt 1) {
        $Process | Add-Member -MemberType NoteProperty -Name OwningProcessServiceDisplayName -Value ($OwningProcessWin32Service.DisplayName -join ':')
    }
    If ($OwningProcessWin32Service.Count -eq $null) {
        $Process | Add-Member -MemberType NoteProperty -Name OwningProcessServiceDisplayName -Value $null
    }
    If ($OwningProcessWin32Service.Count -eq 1) {
        $Process | Add-Member -MemberType NoteProperty -Name OwningProcessServiceDisplayName -Value $OwningProcessWin32Service[0].DisplayName
    }


    $outObjNew = New-Object -TypeName PSObject -Property @{Username=$env:COMPUTERNAME;type="UDPListener";displayname="$($process.LocalAddress):$($process.LocalPort):$($process.OwningProcessName):$($process.OwningProcessServiceDisplayName)";Computername=$env:COMPUTERNAME}
    [void]$Generaloutcol.Add($outObjNew)
}
$outHT.UDPListeners = ($UDPListening |?{$_.OwningProcessName -ne $null} | select LocalAddress,LocalPort,OwningProcessName,OwningProcessPath,OwningProcessServiceDisplayName)
$outHT.UDPListeners
#endregion network UDP listeners


write-host "Done"
Export-Clixml -InputObject $outHT -Path "\\$($SERVERNAME)\WindowsComputerInfos`$\$($env:COMPUTERNAME).clixml" -Force

del "\\$($SERVERNAME)\WindowsComputerInfos`$\$($env:COMPUTERNAME).csv" -ErrorAction SilentlyContinue -Force
$Generaloutcol | Export-Csv -Path  "\\$($SERVERNAME)\WindowsComputerInfos`$\$($env:COMPUTERNAME).csv" -NoClobber -NoTypeInformation -Force
