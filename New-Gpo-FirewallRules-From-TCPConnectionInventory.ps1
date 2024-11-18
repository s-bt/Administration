function Get-ObjectMD5Hash {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [object]$InputObject
    )

    process {
        # Convert the object to a JSON string
        $jsonString = $InputObject | ConvertTo-Json -Compress

        # Create a new MD5 hash object
        $md5 = [System.Security.Cryptography.MD5]::Create()

        # Convert the JSON string to a byte array and compute the hash
        $hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($jsonString.tolower()))

        # Convert the byte array to a hexadecimal string
        $hashString = [BitConverter]::ToString($hashBytes) -replace '-'

        return $hashString.ToLower()
    }
}

Foreach ($f in @(dir "C:\WindowsComputerInfos\*.clixml")){
    
    if ($f.Name -match "(N|P)-.*"){
        continue
    }
    $c = Import-Clixml $f.FullName
    $ServerName = $f.Name.Replace(".clixml","")
    Foreach ($l in $c.TCPListeners){
        # We need the checksum to find duplicate listeners
        $checkSum = Get-ObjectMD5Hash -InputObject $l
        
        # We create a PSObject type variable for each of the listeners with the listener object and an arraylist of all servers that use this listener
        try {
            Write-Host "Trying to add '$($ServerName)' to 'connection_$($checkSum)'" -ForegroundColor Gray
            [void](Get-Variable -Name "connection_$($checkSum)" -ErrorAction Stop).Value.'ComputerNames'.add($ServerName)
        } catch {
            $OutObj = New-Object -TypeName PSObject
            $OutObj | Add-Member -MemberType NoteProperty -Name Connection -Value $l
            $OutObj | Add-Member -MemberType NoteProperty -Name ComputerNames -Value (New-Object System.Collections.ArrayList)
            [void]$OutObj.ComputerNames.Add($ServerName)
            New-Variable -Name "connection_$($checkSum)" -Value ($OutObj)
        }
    }
}

$OutCol = New-Object System.Collections.ArrayList

Foreach ($var in @(dir "variable:\connection_*")) {
    [void]$OutCol.Add($var.Value)
}

#region configure the firewall rules in a gpo
try {
    Write-Host "Creating NetGPO Session" -ForegroundColor Gray
    $GpoSession = Open-NetGPO -DomainController "DC01" -PolicyStore "mydomain.com\POC_FirewallRules" -ErrorAction Stop
} catch {
    Write-Error $Error[0]
    return -1
}

$AlreadyDone = @{}

Foreach ($connection in $OutCol) {
    if ($connection.Connection.LocalPort -gt 3389 -or $AlreadyDone[$connection.Connection.LocalPort] -eq $true){
        continue
    }
    if ($connection.Connection.LocalPort -eq 139) {
        # This port is not bound to 0.0.0.0 but the local IP, so there would be one rule per server which does not make sense
        # hence, we will only create one rule
        $AlreadyDone.Add($connection.Connection.LocalPort,$true)
    }

    Write-Host "Creating new rule 'POC_$($connection.Connection.OwningProcessName)'" -ForegroundColor Gray
    if ($connection.Connection.OwningProcessPath -ne $null) {
        $Rule = New-NetFirewallRule -DisplayName "POC_$($connection.Connection.OwningProcessName)" -Direction Inbound -Protocol TCP -LocalPort $connection.Connection.LocalPort -Action Allow -Program $connection.Connection.OwningProcessPath -Description ($connection.ComputerNames -join ",") -GPOSession $GpoSession
    } else {
        $Rule = New-NetFirewallRule -DisplayName "POC_$($connection.Connection.OwningProcessName)" -Direction Inbound -Protocol TCP -LocalPort $connection.Connection.LocalPort -Action Allow -Description ($connection.ComputerNames -join ",") -GPOSession $GpoSession
    }
}

try {
    Write-Host "Closing NetGPO Session" -ForegroundColor Gray
    Save-NetGPO -GPOSession $GpoSession
} catch {
    Write-Error $Error[0]
    return -1
}
#endregion configure the firewall rules in a gpo

<#
Install-Module Firewall-Manager
get-command -Module Firewall-Manager
cd $home\Documents
Export-FirewallRules -Name "POC_*" -JSON
#>

$OutCol | select @{n="LocalAddress";e={$_.Connection.LocalAddress}},@{n="LocalPort";e={$_.Connection.LocalPort}},@{n="OwningProcessPath";e={$_.Connection.OwningProcessPath}},@{n="OwningProcessName";e={$_.Connection.OwningProcessName}},ComputerNames | ogv

Write-Host "Removing all temporary connection variables" -ForegroundColor Gray
@(dir "variable:\connection_*") | Remove-Variable
