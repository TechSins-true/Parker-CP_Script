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

## Update Password Policy
$SecPool.'System Access'.PasswordComplexity = 1
$SecPool.'System Access'.MinimumPasswordLength = 8
$SecPool.'System Access'.MaximumPasswordAge = 90
$SecPool.'System Access'.MinimumPasswordAge = 30
$SecPool.'System Access'.PasswordHistorySize = 5
$SecPool.'System Access'.ClearTextPassword = 0

## Account Account Policies
$SecPool.'System Access'.LockoutBadCount = 5
$SecPool.'System Access'.LockoutDuration = 30
$SecPool.'System Access'.ResetLockoutCount = 30

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

Set-SecPol -Object $SecPool -CfgFile ./Test.cfg

Write-host "local Seccurity Policy Properties changed"


# Turn on Windows Defender Firewall
Set-NetFirewallProfile -profile Domain,Public,Private -Enabled true
Write-host "Windows Defender Firewall is Turned on"

# Set a new password for each user

    # Get all local users
$localUsers = Get-WmiObject Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }

while ($true) {
    $exludeduser = Read-Host "enter user to exlude"
    Write-Output "You entered: $exludeduser"
    $confirmation = Read-Host "Is this correct? (y/n)"
    if ($confirmation -eq "y") {
        break
     } elseif ($confirmation -eq "n") {
        Write-Output "Let's try again."
    } else {
        Write-Output "Invalid response. Please answer with 'y' or 'n'."
    }
}

foreach ($user in $localUsers) {
    if ($user.Name -ne $exludeduser) {
    $newPassword = "S@feP@ssw0rd!5374"|ConvertTo-SecureString -AsPlainText -Force 
    set-localuser -name $user.Name -password $newPassword
    Write-Host "Password changed for $($user.Name)"
    }
}
Write-Host "Password change process completed."

# list and or choose to remove users in the administrator group



Pause
