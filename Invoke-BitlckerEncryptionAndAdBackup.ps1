# Check if TPM is present

$ProtectedDrive = $env:SystemDrive
$LogPath = "\\KL-DC01\WindowsComputerInfos`$\Bitlocker_$($env:COMPUTERNAME).txt"
Start-Transcript -Path $LogPath

function Get-BitlockerKeyFromAd {
    param(
        [string]$Computername=($env:COMPUTERNAME)
    )
    # Get the AD computer object
    $s = [ADSISearcher]::new()
    $s.Filter = "(samaccountname=$($computername)`$)"
    [void]$s.PropertiesToLoad.Add("distinguishedname")
    [void]$s.PropertiesToLoad.Add("CN")
    $computer = $s.FindOne()
    
    if ($null -eq $computer) {
        return $null
    }
    
    #$computer = Get-ADComputer -Identity $env:COMPUTERNAME

    # Query for BitLocker recovery information objects under this computer
    
    $bitlockerSearchRoot = [System.DirectoryServices.DirectoryEntry]::new("LDAP://kl-dc01.kl-direkt.de/$($computer.Properties.distinguishedname[0].Replace('CN=$computer.Properties.cn[0]',''))")
    $s_new = [ADSISearcher]::new($bitlockerSearchRoot)
    $s_new.Filter = "(objectClass=msFVE-RecoveryInformation)"
    #[void]$s_new.PropertiesToLoad.Add('msFVE-RecoveryPassword')
    #[void]$s_new.PropertiesToLoad.Add('msFVE-RecoveryGuid')
    #[void]$s_new.PropertiesToLoad.Add('whenCreated')
    $recoveryObjects = $s_new.FindAll()

    #$recoveryObjects = Get-ADObject -Filter {"objectClass -eq 'msFVE-RecoveryInformation'} 
    #   -SearchBase $computer.DistinguishedName `
    #   -Properties 'msFVE-RecoveryPassword', 'msFVE-RecoveryGuid', 'whenCreated'
    
    # Display the recovery passwords and related info
    $recoveryObjects | Select-Object `
        @{Name="ComputerName";Expression={$computer.Properties.cn[0]}},
        @{Name="RecoveryID";Expression={[guid]$_.properties.'msfve-recoveryguid'[0]}},
        @{Name="whencreated";Expression={$_.properties.whencreated[0]}}
}


$tpm = Get-Tpm
if (-not $tpm.TpmPresent) {
    Write-Host "TPM is unavailable or disabled. Check BIOS settings."
    exit 1
}

# Initialize TPM if not ready
if (-not $tpm.TpmReady) {
    $initResult = Initialize-Tpm
    if ($initResult.RestartRequired) {
        Write-Host "A reboot is required to complete TPM initialization. Please reboot and re-run the script."
        #exit 1
    }
}

# Check if the bitlocker feature is installed
try {
    $TempVar = Get-WindowsOptionalFeature -FeatureName Bitlocker -Online -ErrorAction Stop
    Write-Host "Bitlocker feature is alredy installed"
    if ($TempVar.State -ne 'Enabled') {
        Write-Host "The bitlocker feature is not enabled. Trying to enable it"
        Throw "Bitlocker feature not installed"
    }
} catch  {
    try {
        Write-Host "Enabling bitlocker feature"
        Enable-WindowsOptionalFeature -FeatureName Bitlocker -All -NoRestart -ErrorAction Stop
    } catch {
        Write-Host "Error enabling bitlocker feature: $($Error[0])"
        exit 1
    }
}

# Enable BitLocker on the OS drive using TPM

try {
    $BitlockerVolume = Get-BitLockerVolume -MountPoint $ProtectedDrive -ErrorAction Stop
    if ($BitlockerVolume.ProtectionStatus -like 'FullyDecrypted' -or $BitlockerVolume.VolumeStatus -eq 'FullyDecrypted' -or $BitlockerVolume.ProtectionStatus -ne 'On' -and ('Tpm, RecoveryPassword' -notin  @($BitlockerVolume.KeyProtector.KeyProtectorType))) {
        throw "Need to enable bitlocker for $ProtectedDrive"
    } else {
        Write-Host "The current status for $($ProtectedDrive) is: $($BitlockerVolume.VolumeStatus)"
        if ($BitlockerVolume.ProtectionStatus -eq 'FullyDecrypted' -or $BitlockerVolume.VolumeStatus -eq 'FullyDecrypted'){
            Write-Host "Seems the machine needs a reboot before bitlocker encryption can start"
        }
    }
} catch {
    try {
        Write-Host "Enabling bitlocker for '$ProtectedDrive'"
        $TempVar = Enable-BitLocker -MountPoint $ProtectedDrive -TpmProtector -ErrorAction Stop
    } catch {
        Write-Host "Error enabling bitlocker for '$ProtectedDrive': $($Error[0])"
        return 1
    }
}


$RecoverPasswordProtectors = @($BitlockerVolume.KeyProtector |Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'})

if ($RecoverPasswordProtectors.Count -eq 0) {
    Write-Host "There are no recovery password protectors configured. Creating one"
    try {
        $TempVar = Add-BitLockerKeyProtector -MountPoint $ProtectedDrive -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
        Write-Host "Successfully created recovery password protector"
    } catch {
        Write-Host "Error creating recovery password protector`n$($Error[0])"
    }
} else {
    Foreach ($protector in $RecoverPasswordProtectors) {
        try {
            $TempVar = Backup-BitLockerKeyProtector -MountPoint $ProtectedDrive -KeyProtectorId $RecoverPasswordProtectors.KeyProtectorId -ErrorAction Stop
            Write-Host "Successfull backed up the recovery password for $($RecoverPasswordProtectors.KeyProtectorId) to AD"
        } catch {
            Write-Host "Error backing up the recovery password for $($RecoverPasswordProtectors.KeyProtectorId) to AD`n$($Error[0])"
        }
    }
}
  
Stop-Transcript
