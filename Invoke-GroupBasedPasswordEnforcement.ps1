<#
.SYNOPSIS
Passwortänderung bei Logon für Gruppenmitglieder basierend auf Zieldatum erzwingen

.DESCRIPTION
Ziel ist es, dass alle Mitglieder einer Gruppe ihr Passwort vor einem Stichdatum geändert haben.
Dazu wird bei allen Mitglieder der Gruppe das Attribut PwdLastSet überprüft. Falls das Passwort nach dem Startdatum $StartDate geändert wurde, wird der User von der Gruppe entfernt.
Fall dies nicht der Fall war passiert im ersten Schritt nichts. Falls aber das Passwort nicht geändert wurde, und das Zieldatum $DueDate überschritten wurde, wird der User so konfiguriert, dass er sein Passwort bei der nächsten Anmeldung änder muss.
Alle Informationen werden in ein Logfile nach c:\logs geschrieben. Alle Log Files älter als 7 Tage werden gelöscht.
#>

param(
    # Das Datum an dem der Benutzer gezwunge wird sein Passwort zu ändern
    [datetime]$DueDate = (Get-date "29.10.2024 00:00:00"),
    # Das Startdatum von dem ab das Passwort geändert werden muss
    [datetime]$StartDate = ((Get-date $DueDate).AddDays(-7))
)
# Der Name der Gruppe dessen Mitglieder das Passwort ändern müssen
$GroupName = "TestPasswortReset"

# Das Log File

$LogFile = "C:\logs\ForcePasswordChange_$(Get-Date -Format "ddMMyyy").log"
$AllLogFiles = "C:\logs\ForcePasswordChange_*"

# Delete log files older than a week
$AllLogFiles = @(dir $AllLogFiles)
Foreach ($file in $AllLogFiles) {
    if ($file.CreationTime -gt (Get-date).AddDays(-7)) {
        $tempVar = del $file -Force
    }
}

$LogDirectory = Split-Path -Path $LogFile -Parent

if (-not (Test-Path $LogDirectory)) {
    try {
        $tempvar = New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop
    } catch {
        Write-Error "Error Creating directory`n$($Error[0])"
        return -1
    }
}

# Start transcribing

$TempVar = Start-Transcript -Path $LogFile -Force -Append -NoClobber

$Error.Clear()

try {
    # Get all group members recursively
    $TargetAccounts = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop -Recursive
} catch {
    Write-Output "[Error] Error getting members of ad group '$($GroupName)'`n$($Error[0])"
    return -1
}

Foreach ($Account in $TargetAccounts) {
    try {
        $AccountObject = Get-aduser $Account.SamAccountName -Properties PasswordLastSet -ErrorAction Stop
        
        # Safety check if the account is located in the admin OU or is the administrator. We don't want to enforce password changes on next logon here
        if ($Account.distinguishedName -like '*,OU=Admin,*' -or $Account.SamAccountName -like '*$' -or $Account.distinguishedName -eq 'Administrator') {
            Write-Host "[AccountAlert] We will not check account'$($Account.SamAccountName)'"
            continue
        }

        # Wenn das Passwort nach StartDate geändert wurde ist alles ok, und der Benuzter wird von der Gruppe entfernt
        if ($AccountObject.PasswordLastSet -gt $StartDate) {
            Write-Output "[PasswordChangeInfo] User '$($AccountObject.SamAccountName)' already changed the password on $($AccountObject.PasswordLastSet.ToLongDateString()) $($AccountObject.PasswordLastSet.ToLongTimeString())"
            try {
                $TempVar = Remove-ADGroupMember -Identity $GroupName -Members $AccountObject.SamAccountName -Confirm:$false -ErrorAction Stop
                Write-Output "[GroupMemberRemoveSuccess] Successfully removed user '$($AccountObject.SamAccountName)' from group '$($GroupName)'"
            } catch {
                Write-Output "[GroupMemberRemoveError] Error removing user '$($AccountObject.SamAccountName)' from group '$($GroupName)'`n$($Error[0])"
            }
        } else {
            Write-Output "[NonPasswordChangeInfo] User '$($AccountObject.SamAccountName)' did not change the password since $($StartDate.ToLongDateString()) $($StartDate.ToLongTimeString())"
            if ((get-date) -ge $DueDate) {
                try {
                    # Wenn der User das Passwort nicht geändert hat, und das Zieldatum erreicht wurde, wird eine Passwortänderung bei der nächsten Anmeldung erzwungen
                    $TempVar = Set-aduser -Identity $AccountObject.SamAccountName -ChangePasswordAtLogon $True -Confirm:$false -ErrorAction Stop
                    Write-Output "[UserChangePasswordAtLogonSuccess] Successfully set ChangePasswordAtLogon for user '$($AccountObject.SamAccountName)'"
                } catch {
                    Write-Output "[UserChangePasswordAtLogonError] Error set ChangePasswordAtLogon for user '$($AccountObject.SamAccountName)'`n$($Error[0])"
                }
            }
        }
    } catch {
        Write-Output "[GetUserObjectError] Error getting ad user '$($Account.SamAccountName)'`n$($Error[0])"
    }
}

# Stop transcribing
$tempVar = Stop-Transcript
