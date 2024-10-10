# things added or changed in v3.1. added AuditLogonEvents = 3. 

#local Seccurity Policy Properties change

Function Parse-SecPol($CfgFile){ 
    secedit /export /cfg "$CfgFile" | out-null
    $obj = New-Object psobject
    $index = 0
    $contents = Get-Content $CfgFile -raw
    [regex]::Matches($contents,"(?<=\[)(.*)(?=\])") | %{
        $title = $_
        [regex]::Matches($contents,"(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | %{
            $section = new-object psobject
            $_.value -split "\r\n" | ?{$_.length -gt 0} | %{
                $value = [regex]::Match($_,"(?<=\=).*").value
                $name = [regex]::Match($_,".*(?=\=)").value
                $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue | out-null
            }
            $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
        }
        $index += 1
    }
    return $obj
}

Function Set-SecPol($Object, $CfgFile){
   $SecPool.psobject.Properties.GetEnumerator() | %{
        "[$($_.Name)]"
        $_.Value | %{
            $_.psobject.Properties.GetEnumerator() | %{
                "$($_.Name)=$($_.Value)"
            }
        }
    } | out-file $CfgFile -ErrorAction Stop
    secedit /configure /db c:\windows\security\local.sdb /cfg "$CfgFile" /areas SECURITYPOLICY
}


$SecPool = Parse-SecPol -CfgFile ./Test.cgf

## Password Policy
$SecPool.'System Access'.PasswordComplexity=1
$SecPool.'System Access'.MinimumPasswordLength=14
$SecPool.'System Access'.MaximumPasswordAge=90
$SecPool.'System Access'.MinimumPasswordAge=30
$SecPool.'System Access'.PasswordHistorySize=24
$SecPool.'System Access'.ClearTextPassword=0

## Account Lockout Policies
$SecPool.'System Access'.LockoutBadCount=5
$SecPool.'System Access'.LockoutDuration=15
$SecPool.'System Access'.ResetLockoutCount=30

## Enable Audit Events -Success and Failure
$SecPool.'Event Audit'.AuditSystemEvents=3
$SecPool.'Event Audit'.AuditDSAccess=3
$SecPool.'Event Audit'.Auditdirectoryservice=3
$SecPool.'Event Audit'.AuditPrivilegeUse=3
$SecPool.'Event Audit'.AuditPolicyChange=3
$SecPool.'Event Audit'.AuditAccountLogon=3
$SecPool.'Event Audit'.AuditAccountManage=3
$SecPool.'Event Audit'.AuditObjectAccess=3
$SecPool.'Event Audit'.AuditProcessTracking=3
$SecPool.'Event Audit'.AuditLogonEvents=3

Set-SecPol -Object $SecPool -CfgFile ./Test.cfg

Write-host "local Seccurity Policy Properties changed"

$cfgFile = "$env:TEMP\secpol.cfg"
$dbFile = "$env:windir\security\local.sdb"

secedit /export /cfg $cfgFile | Out-Null

$content = Get-Content $cfgFile

$modifiedContent = foreach ($line in $content) {
    if ($line -like "SeNetworkLogonRight*") {
        "SeNetworkLogonRight = " 
    }
    elseif ($line -like "SeTakeOwnershipPrivilege*") { 
        $key = "SeTakeOwnershipPrivilege"
        $updatedValue = "Administrators"
        "$key=$updatedValue"
    }
    else {
        $line
    }
}
Set-Content -Path $cfgFile -Value $modifiedContent
secedit /configure /db $dbFile /cfg $cfgFile /areas USER_RIGHTS
Remove-Item $cfgFile -Force

# Turn on Windows Defender Firewall
Set-NetFirewallProfile -profile Domain,Public,Private -Enabled true
Write-host "Windows Defender Firewall is Turned on"

# Set a new password for each user while exluding the current user

    # Get all local users
$localUsers = Get-WmiObject Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }
$excludeduser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1] 
Write-Host "Excluded" $excludeduser "from password change"

foreach ($user in $localUsers) {
    if ($user.Name -ne $excludeduser) {
    $newPassword = "S@feP@ssw0rd!5374" | ConvertTo-SecureString -AsPlainText -Force 
    Set-LocalUser -Name $user.Name -Password $newPassword
    Write-Host "Password changed for $($user.Name)"
    }
}

Write-Host "Password change process completed."


# Disabling Guest, Administrator, and also renameing them
Disable-LocalUser guest,administrator
Rename-LocalUser guest WannaBeGuest
Rename-LocalUser administrator WannabeAdministrator



Pause