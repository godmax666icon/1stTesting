#Requires -Version 5.1
#Requires -Modules VMware.PowerCLI
<#
.SYNOPSIS
  Applies the CIS ESXi 8.0 Level 1 host baseline without enabling lockdown mode.

.DESCRIPTION
  Built against CIS VMware ESXi 8.0 Benchmark v1.4.0, Level 1 only.
  Run it from the clean admin workstation after New-SiicEsxiConfig.ps1, so the
  local VMFS names exist and vCenter can see the three hosts. It does not store
  passwords.

  Preview, which is the default, connects and prints every change:

      .\Set-SiicEsxiCisLevel1.ps1

  Apply:

      .\Set-SiicEsxiCisLevel1.ps1 -Apply

  Send logs to a collector when one exists. Leave -SyslogHost empty until then:

      .\Set-SiicEsxiCisLevel1.ps1 -Apply -SyslogHost 'udp://log.example:514'

  Lockdown mode is not enabled and is not disabled. Recommendations 3.20 and
  3.21 are omitted. If a host is already in lockdown, the script stops on that
  host because several Level 1 settings, including the Managed Object Browser,
  cannot be changed safely from here while lockdown is on.

  Site exceptions, printed and left unchanged:
    vSwitch1 and its port groups keep the MAC-change and forged-transmit policy
    from New-SiicEsxiConfig.ps1. Promiscuous mode is still set to reject.
    VLAN ID 0 stays. The address sheet uses untagged VLAN 12, vMotion, and DMZ.
    VLAN 4095 is reported and not rewritten.
    vusb0 on vSwitchBMC is left in place.
    Secure Boot and TPM configuration encryption stay manual BIOS and firmware
    steps. This script does not reboot the host.
#>
[CmdletBinding()]
param(
    [string]$VCenter = 'vcenter.siic.local',
    [string[]]$HostName = @('esxi1.siic.local', 'esxi2.siic.local', 'esxi3.siic.local'),
    [string]$NtpServer = 'stdtime.gov.hk',
    [string]$SyslogHost = '',
    [string]$Banner = 'SiiC authorized access only. Disconnect if you are not an approved administrator.',
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# vSwitch1 is the dedicated DMZ uplink. The recovered design accepts MAC changes
# and forged transmits there. Every other standard switch is set to reject.
$SwitchSecurityExempt = @('vSwitch1')

$LocalDatastore = @{
    'esxi1.siic.local' = 'esxi1_datastore1'
    'esxi2.siic.local' = 'esxi2_datastore1'
    'esxi3.siic.local' = 'esxi3_datastore1'
}
$HostAddress = @{
    'esxi1.siic.local' = '172.28.2.191'
    'esxi2.siic.local' = '172.28.2.194'
    'esxi3.siic.local' = '172.28.2.197'
}

# Values are the v1.4.0 Level 1 remediation values.
# Config.HostAgent.vmacore.soap.sessionTimeout is in minutes. 30 is 30 minutes.
# The benchmark narrative also says "30 seconds"; this setting has no seconds unit.
$Advanced = [ordered]@{
    'UserVars.SuppressHyperthreadWarning'          = '0'      # 2.9
    'Mem.ShareForceSalting'                        = '2'      # 2.10
    'Config.HostAgent.plugins.solo.enableMob'      = 'false'  # 3.3
    'UserVars.DcuiTimeOut'                         = '600'    # 3.7
    'UserVars.ESXiShellInteractiveTimeOut'         = '300'    # 3.8
    'UserVars.ESXiShellTimeOut'                    = '3600'   # 3.9
    'UserVars.SuppressShellWarning'                = '0'      # 3.10
    'Security.PasswordQualityControl'              = 'retry=3 min=disabled,disabled,disabled,disabled,15' # 3.11
    'Security.AccountLockFailures'                 = '5'      # 3.12
    'Security.AccountUnlockTime'                   = '900'    # 3.13
    'Security.PasswordHistory'                     = '5'      # 3.14
    'Security.PasswordMaxDays'                     = '99999'  # 3.15
    'Config.HostAgent.vmacore.soap.sessionTimeout' = '30'     # 3.16, minutes
    'UserVars.HostClientSessionTimeout'            = '900'    # 3.17
    'DCUI.Access'                                  = 'root'   # 3.18
    'UserVars.ESXiVPsDisabledProtocols'            = 'sslv3,tlsv1,tlsv1.1' # 3.26
    'Syslog.global.logLevel'                       = 'info'   # 4.3
    'Config.HostAgent.log.level'                   = 'info'   # 4.4
    'Syslog.global.logFiltersEnable'               = 'false'  # 4.5
    'Net.DVFilterBindIpAddress'                    = ''       # 5.3
    'Net.BlockGuestBPDU'                           = '1'      # 5.4
}

# Applied only when the key exists on this build, so an unknown cipher name
# cannot be written onto a host whose OpenSSH does not advertise it.
$SshWanted = [ordered]@{
    'ciphers'                    = 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' # 6.5.1
    'gatewayports'               = 'no'    # 6.5.3
    'hostbasedauthentication'    = 'no'    # 6.5.4
    'clientalivecountmax'        = '3'     # 6.5.5
    'clientaliveinterval'        = '200'   # 6.5.6
    'banner'                     = '/etc/issue' # 6.5.7
    'ignorerhosts'               = 'yes'   # 6.5.8
    'allowstreamlocalforwarding' = 'no'    # 6.5.9
    'allowtcpforwarding'         = 'no'    # 6.5.10
    'permittunnel'               = 'no'    # 6.5.11
    'permituserenvironment'      = 'no'    # 6.5.12
}

function Write-Step {
    param([string]$Message)
    Write-Host ''
    Write-Host "== $Message" -ForegroundColor Green
}

function Use-Change {
    param([string]$Message)
    if ($Apply) {
        Write-Host "APPLY   $Message" -ForegroundColor Yellow
        return $true
    }
    Write-Host "PLAN    $Message" -ForegroundColor Cyan
    return $false
}

function Get-Prop {
    param($Object, [string]$Name)
    if (-not $Object) { return '' }
    $prop = $Object.PSObject.Properties | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if (-not $prop -or $null -eq $prop.Value) { return '' }
    return [string]$prop.Value
}

function Test-SameSetting {
    param([string]$Current, [string]$Wanted)
    if ($null -eq $Current) { $Current = '' }
    if ($Current -eq $Wanted) { return $true }
    if ($Wanted -match '^(?i:true|false)$' -and $Current.ToLowerInvariant() -eq $Wanted.ToLowerInvariant()) {
        return $true
    }
    return $false
}

function Set-HostAdvanced {
    param($VMHost, [string]$Name, [string]$Value, [string]$Note)
    $setting = Get-AdvancedSetting -Entity $VMHost -Name $Name -ErrorAction SilentlyContinue
    if (-not $setting) {
        Write-Warning "SKIP    $($VMHost.Name) has no advanced setting $Name. $Note"
        return
    }
    $current = [string]$setting.Value
    if (Test-SameSetting -Current $current -Wanted $Value) {
        Write-Host "KEEP    $($VMHost.Name) $Name = $Value"
        return
    }
    $label = "$($VMHost.Name) $Name from '$current' to '$Value'. $Note"
    if (Use-Change $label) {
        Set-AdvancedSetting -AdvancedSetting $setting -Value $Value -Confirm:$false | Out-Null
    }
}

function Set-ServiceManual {
    param($VMHost, [string]$Key, [string]$Note)
    $service = Get-VMHostService -VMHost $VMHost | Where-Object { $_.Key -eq $Key }
    if (-not $service) {
        Write-Warning "SKIP    $($VMHost.Name) has no service $Key. $Note"
        return
    }
    if ($service.Policy -eq 'Off' -and -not $service.Running) {
        Write-Host "KEEP    $($VMHost.Name) $Key stopped, start and stop manually. $Note"
        return
    }
    if (Use-Change "$($VMHost.Name) stop $Key and set the startup policy to manual. $Note") {
        Set-VMHostService -HostService $service -Policy Off -Confirm:$false | Out-Null
        if ($service.Running) {
            Stop-VMHostService -HostService $service -Confirm:$false | Out-Null
        }
    }
}

function Get-EsxChild {
    param($Node, [string]$Name)
    if (-not $Node) { return $null }
    $prop = $Node.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    if (-not $prop) { return $null }
    return $prop.Value
}

function Get-EsxPath {
    param($Node, [string[]]$Path)
    $current = $Node
    foreach ($part in $Path) {
        $current = Get-EsxChild -Node $current -Name $part
        if (-not $current) { return $null }
    }
    return $current
}

function Test-EsxFlag {
    param($Result, [string]$Name)
    if (-not $Result) { return $false }
    $prop = $Result.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    if ($prop) { return [string]$prop.Value -match '^(?i:true|1)$' }
    return [string]$Result -match ('(?i){0}\s*[:=]\s*true' -f [regex]::Escape($Name))
}

function Invoke-Esx {
    param($Method, [hashtable]$Values, [string]$Label)
    if (-not $Method) {
        Write-Warning "SKIP    $Label. This build has no matching esxcli method."
        return $null
    }
    $bound = @{}
    $spec = $null
    try { $spec = $Method.CreateArgs() } catch { $spec = $null }
    if ($spec) {
        foreach ($name in @($spec.Keys)) {
            $hit = @($Values.Keys | Where-Object { $_ -ieq $name } | Select-Object -First 1)
            if ($hit.Count -eq 1) { $bound[$name] = $Values[$hit[0]] }
        }
    }
    else {
        $bound = $Values
    }
    if (-not (Use-Change $Label)) { return $null }
    try {
        if ($bound.Count -eq 0) { return $Method.Invoke() }
        return $Method.Invoke($bound)
    }
    catch {
        Write-Warning "FAILED  $Label. $($_.Exception.Message)"
        return $null
    }
}

function Get-EsxValue {
    param($Method, [hashtable]$Values)
    if (-not $Method) { return $null }
    $bound = @{}
    $spec = $null
    try { $spec = $Method.CreateArgs() } catch { $spec = $null }
    if ($spec -and $Values.Count -gt 0) {
        foreach ($name in @($spec.Keys)) {
            $hit = @($Values.Keys | Where-Object { $_ -ieq $name } | Select-Object -First 1)
            if ($hit.Count -eq 1) { $bound[$name] = $Values[$hit[0]] }
        }
    }
    try {
        if ($bound.Count -gt 0) { return $Method.Invoke($bound) }
        return $Method.Invoke()
    }
    catch {
        Write-Warning "READ FAILED  $($_.Exception.Message)"
        return $null
    }
}

function Get-PersistentDatastore {
    param($VMHost, [string]$PlanName)
    $preferred = $LocalDatastore[$PlanName]
    if (-not $preferred) { $preferred = $LocalDatastore[$VMHost.Name] }
    if ($preferred) {
        $named = Get-Datastore -VMHost $VMHost -Name $preferred -ErrorAction SilentlyContinue
        if ($named) { return $named }
    }
    $local = @(Get-Datastore -VMHost $VMHost | Where-Object {
            $_.Type -eq 'VMFS' -and -not $_.ExtensionData.Summary.MultipleHostAccess
        })
    if ($local.Count -eq 1) { return $local[0] }
    return $null
}

function Set-SwitchReject {
    param($Policy, [string]$Label, [bool]$TouchMacAndForged)
    $promiscuousOk = -not $Policy.AllowPromiscuous
    $macOk = (-not $TouchMacAndForged) -or (-not $Policy.MacChanges)
    $forgedOk = (-not $TouchMacAndForged) -or (-not $Policy.ForgedTransmits)
    if ($promiscuousOk -and $macOk -and $forgedOk) {
        Write-Host "KEEP    $Label"
        return
    }
    $detail = if ($TouchMacAndForged) {
        'promiscuous, MAC changes, and forged transmits reject'
    }
    else {
        'promiscuous reject; MAC changes and forged transmits left as designed'
    }
    if (Use-Change "$Label to $detail") {
        if ($TouchMacAndForged) {
            Set-SecurityPolicy -SecurityPolicy $Policy -AllowPromiscuous:$false -MacChanges:$false -ForgedTransmits:$false | Out-Null
        }
        else {
            Set-SecurityPolicy -SecurityPolicy $Policy -AllowPromiscuous:$false | Out-Null
        }
    }
}

function Set-HostCis {
    param($VMHost, [string]$PlanName)

    Write-Step $VMHost.Name
    $view = Get-View -Id $VMHost.Id
    $lockdown = [string]$view.Config.LockdownMode
    if ($lockdown -ne 'lockdownDisabled') {
        Write-Warning "$($VMHost.Name) lockdown mode is $lockdown. This script does not change lockdown. Skipping this host."
        return
    }
    Write-Host "KEEP    $($VMHost.Name) lockdown mode disabled. CIS 3.20 and 3.21 are not applied."

    $esx = Get-EsxCli -VMHost $VMHost -V2

    $acceptance = [string](Get-EsxValue -Method (Get-EsxPath $esx @('software', 'acceptance', 'get')) -Values @{})
    $rank = @{
        'CommunitySupported' = 0
        'PartnerSupported'   = 1
        'VMwareAccepted'     = 2
        'VMwareCertified'    = 3
    }
    if ($rank.ContainsKey($acceptance) -and $rank[$acceptance] -ge 1) {
        Write-Host "KEEP    $($VMHost.Name) acceptance level $acceptance. CIS 2.4"
    }
    else {
        Invoke-Esx -Method (Get-EsxPath $esx @('software', 'acceptance', 'set')) -Values @{ level = 'PartnerSupported' } `
            -Label "$($VMHost.Name) acceptance level from '$acceptance' to PartnerSupported. CIS 2.4. Dell VIBs stay allowed." | Out-Null
    }

    $kernel = Get-EsxValue -Method (Get-EsxPath $esx @('system', 'settings', 'kernel', 'list')) -Values @{ option = 'execInstalledOnly' }
    $configured = ''
    if ($kernel) { $configured = Get-Prop -Object $kernel -Name 'Configured' }
    if ($configured -match '^(?i:true|TRUE)$') {
        Write-Host "KEEP    $($VMHost.Name) execInstalledOnly is TRUE. CIS 2.5"
    }
    else {
        Invoke-Esx -Method (Get-EsxPath $esx @('system', 'settings', 'kernel', 'set')) -Values @{ setting = 'execInstalledOnly'; value = 'TRUE' } `
            -Label "$($VMHost.Name) set execInstalledOnly TRUE. CIS 2.5. Reboot before relying on the runtime value." | Out-Null
    }

    $ntp = @(Get-VMHostNtpServer -VMHost $VMHost -ErrorAction SilentlyContinue)
    $ntpService = Get-VMHostService -VMHost $VMHost | Where-Object { $_.Key -eq 'ntpd' }
    if (-not $ntpService) {
        Write-Warning "SKIP    $($VMHost.Name) has no ntpd service. CIS 2.6 and 2.7"
    }
    elseif ($ntp -contains $NtpServer -and $ntpService.Running -and $ntpService.Policy -eq 'On') {
        Write-Host "KEEP    $($VMHost.Name) NTP $NtpServer. CIS 2.6 and 2.7"
    }
    elseif (Use-Change "$($VMHost.Name) NTP $NtpServer, ntpd start and stop with the host. CIS 2.6 and 2.7") {
        if ($ntp -notcontains $NtpServer) {
            Add-VMHostNtpServer -VMHost $VMHost -NtpServer $NtpServer -Confirm:$false | Out-Null
        }
        Set-VMHostService -HostService $ntpService -Policy On -Confirm:$false | Out-Null
        if ($ntpService.Running) {
            Restart-VMHostService -HostService $ntpService -Confirm:$false | Out-Null
        }
        else {
            Start-VMHostService -HostService $ntpService -Confirm:$false | Out-Null
        }
    }

    Set-ServiceManual -VMHost $VMHost -Key 'TSM-SSH' -Note 'CIS 3.1'
    Set-ServiceManual -VMHost $VMHost -Key 'TSM' -Note 'CIS 3.2'
    Set-ServiceManual -VMHost $VMHost -Key 'slpd' -Note 'CIS 3.4'

    $wbem = Get-EsxValue -Method (Get-EsxPath $esx @('system', 'wbem', 'get')) -Values @{}
    if (-not $wbem) {
        Write-Warning "SKIP    $($VMHost.Name) WBEM query is not available. Confirm CIM is off. CIS 3.5"
    }
    elseif (-not (Test-EsxFlag -Result $wbem -Name 'Enabled')) {
        Write-Host "KEEP    $($VMHost.Name) WBEM/CIM disabled. CIS 3.5"
    }
    else {
        Invoke-Esx -Method (Get-EsxPath $esx @('system', 'wbem', 'set')) -Values @{ enable = $false } `
            -Label "$($VMHost.Name) disable WBEM/CIM. CIS 3.5" | Out-Null
    }

    $snmp = Get-EsxValue -Method (Get-EsxPath $esx @('system', 'snmp', 'get')) -Values @{}
    if (-not $snmp) {
        Write-Warning "SKIP    $($VMHost.Name) SNMP query is not available. CIS 3.6"
    }
    elseif (-not (Test-EsxFlag -Result $snmp -Name 'enable')) {
        Write-Host "KEEP    $($VMHost.Name) SNMP disabled. CIS 3.6"
    }
    else {
        Invoke-Esx -Method (Get-EsxPath $esx @('system', 'snmp', 'set')) -Values @{ enable = $false } `
            -Label "$($VMHost.Name) disable SNMP. CIS 3.6" | Out-Null
    }

    foreach ($name in $Advanced.Keys) {
        Set-HostAdvanced -VMHost $VMHost -Name $name -Value $Advanced[$name] -Note 'CIS Level 1'
    }
    Set-HostAdvanced -VMHost $VMHost -Name 'Annotations.WelcomeMessage' -Value $Banner -Note 'CIS 3.24'
    Set-HostAdvanced -VMHost $VMHost -Name 'Config.Etc.issue' -Value $Banner -Note 'CIS 3.25'

    $accounts = @(Get-EsxValue -Method (Get-EsxPath $esx @('system', 'account', 'list')) -Values @{})
    $dcui = $accounts | Where-Object {
        $_ -and ((Get-Prop -Object $_ -Name 'UserID') -eq 'dcui' -or (Get-Prop -Object $_ -Name 'Id') -eq 'dcui')
    } | Select-Object -First 1
    if (-not $dcui) {
        Write-Warning "SKIP    $($VMHost.Name) dcui account was not listed. Confirm it has no shell. CIS 3.22"
    }
    else {
        $shell = Get-Prop -Object $dcui -Name 'Shellaccess'
        if (-not $shell) { $shell = Get-Prop -Object $dcui -Name 'Shell' }
        if ($shell -match 'false|nologin|/bin/false') {
            Write-Host "KEEP    $($VMHost.Name) dcui has no interactive shell. CIS 3.22"
        }
        elseif (-not $shell) {
            Write-Host "KEEP    $($VMHost.Name) dcui shell field is blank on this build. Confirm /bin/false before calling it a finding. CIS 3.22"
        }
        else {
            Invoke-Esx -Method (Get-EsxPath $esx @('system', 'account', 'set')) -Values @{ id = 'dcui'; shellaccess = $false } `
                -Label "$($VMHost.Name) remove the dcui interactive shell. CIS 3.22" | Out-Null
        }
    }

    $datastore = Get-PersistentDatastore -VMHost $VMHost -PlanName $PlanName
    if (-not $datastore) {
        Write-Warning "SKIP    $($VMHost.Name) has no single local VMFS for persistent logs. Run New-SiicEsxiConfig.ps1 first. CIS 4.1 and 4.7"
    }
    else {
        $logDir = "[{0}] systemlogs" -f $datastore.Name
        Set-HostAdvanced -VMHost $VMHost -Name 'Syslog.global.logDir' -Value $logDir -Note 'CIS 4.1'
        $auditPath = "/vmfs/volumes/$($datastore.Name)/audit"
        if ($Apply) {
            $datacenter = Get-Datacenter -VMHost $VMHost
            $fileManager = Get-View (Get-View ServiceInstance).Content.FileManager
            try {
                $fileManager.MakeDirectory("[$($datastore.Name)] audit", $datacenter.ExtensionData.MoRef, $true)
            }
            catch {
                if ($_.Exception.Message -notmatch 'AlreadyExists|already exists') {
                    Write-Warning "Audit directory on $($VMHost.Name) was not created. $($_.Exception.Message)"
                }
            }
        }
        Invoke-Esx -Method (Get-EsxPath $esx @('system', 'auditrecords', 'local', 'set')) -Values @{ directory = $auditPath; size = 100 } `
            -Label "$($VMHost.Name) audit records at $auditPath, capacity 100. CIS 4.6, 4.7, and 4.8" | Out-Null
        Invoke-Esx -Method (Get-EsxPath $esx @('system', 'auditrecords', 'local', 'enable')) -Values @{} `
            -Label "$($VMHost.Name) enable local audit records. CIS 4.6" | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($SyslogHost)) {
        Write-Warning "GAP     $($VMHost.Name) has no -SyslogHost. CIS 4.2 and 4.9 stay open until a collector is named."
    }
    else {
        Set-HostAdvanced -VMHost $VMHost -Name 'Syslog.global.logHost' -Value $SyslogHost -Note 'CIS 4.2'
        Invoke-Esx -Method (Get-EsxPath $esx @('network', 'firewall', 'ruleset', 'set')) -Values @{ rulesetid = 'syslog'; enabled = $true } `
            -Label "$($VMHost.Name) enable the syslog firewall ruleset" | Out-Null
    }

    $firewall = Get-EsxValue -Method (Get-EsxPath $esx @('network', 'firewall', 'get')) -Values @{}
    if (Test-EsxFlag -Result $firewall -Name 'Enabled') {
        Write-Host "KEEP    $($VMHost.Name) firewall enabled. CIS 5.2. Rulesets were not closed; vCenter and Veeam still need them."
    }
    else {
        Invoke-Esx -Method (Get-EsxPath $esx @('network', 'firewall', 'set')) -Values @{ enabled = $true } `
            -Label "$($VMHost.Name) enable the host firewall. CIS 5.2" | Out-Null
    }

    foreach ($switch in @(Get-VirtualSwitch -VMHost $VMHost -Standard -ErrorAction SilentlyContinue)) {
        $exempt = $SwitchSecurityExempt -contains $switch.Name
        $policy = Get-SecurityPolicy -VirtualSwitch $switch
        Set-SwitchReject -Policy $policy -Label "$($VMHost.Name) $($switch.Name)" -TouchMacAndForged:(-not $exempt)
        if ($exempt) {
            Write-Host "SKIP    $($VMHost.Name) $($switch.Name) MAC changes and forged transmits stay as the DMZ design. CIS 5.6 and 5.7"
        }
    }
    foreach ($group in @(Get-VirtualPortGroup -VMHost $VMHost -Standard -ErrorAction SilentlyContinue)) {
        $exempt = $SwitchSecurityExempt -contains $group.VirtualSwitchName
        $policy = Get-SecurityPolicy -VirtualPortGroup $group
        Set-SwitchReject -Policy $policy -Label "$($VMHost.Name) port group $($group.Name)" -TouchMacAndForged:(-not $exempt)
        $vlan = [int]$group.VLanId
        if ($vlan -eq 4095) {
            Write-Warning "GAP     $($VMHost.Name) port group $($group.Name) is VLAN 4095 (VGT). It was not changed. CIS 5.10"
        }
        elseif ($vlan -eq 0) {
            Write-Host "KEEP    $($VMHost.Name) port group $($group.Name) VLAN 0, the approved untagged network. CIS 5.9 is not retagging it."
        }
        elseif ($vlan -eq 1) {
            Write-Warning "GAP     $($VMHost.Name) port group $($group.Name) uses VLAN 1. Confirm it is not the physical native VLAN. It was not changed."
        }
    }

    $sshRows = @(Get-EsxValue -Method (Get-EsxPath $esx @('system', 'ssh', 'server', 'config', 'list')) -Values @{})
    foreach ($key in $SshWanted.Keys) {
        $row = $sshRows | Where-Object { $_ -and (Get-Prop -Object $_ -Name 'Key') -eq $key } | Select-Object -First 1
        if (-not $row) {
            Write-Warning "SKIP    $($VMHost.Name) SSH key '$key' is not on this build. CIS 6.5"
            continue
        }
        $current = Get-Prop -Object $row -Name 'Value'
        if ($current -eq $SshWanted[$key]) {
            Write-Host "KEEP    $($VMHost.Name) ssh $key = $($SshWanted[$key])"
            continue
        }
        Invoke-Esx -Method (Get-EsxPath $esx @('system', 'ssh', 'server', 'config', 'set')) -Values @{ keyword = $key; key = $key; value = $SshWanted[$key] } `
            -Label "$($VMHost.Name) ssh $key from '$current' to '$($SshWanted[$key])'. SSH stays stopped." | Out-Null
    }

    $iscsi = @(Get-VMHostHba -VMHost $VMHost -Type iScsi -ErrorAction SilentlyContinue)
    if ($iscsi.Count -eq 0) {
        Write-Host "KEEP    $($VMHost.Name) iSCSI client is not enabled. CIS 6.3 does not apply. Storage is Fibre Channel."
    }
    else {
        Write-Warning "GAP     $($VMHost.Name) has an iSCSI adapter. This script does not invent CHAP secrets. CIS 6.3"
    }
}

Write-Step '1. Connect to vCenter'
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
$vcCred = Get-Credential -Message "vCenter administrator for $VCenter"
Connect-VIServer -Server $VCenter -Credential $vcCred | Out-Null
if (-not $Apply) {
    Write-Host 'Preview only. Pass -Apply to change the hosts.' -ForegroundColor Cyan
}
Write-Host 'Lockdown mode will not be enabled.'

Write-Step '2. CIS ESXi 8.0 v1.4 Level 1'
foreach ($name in $HostName) {
    $vmhost = Get-VMHost -Name $name -ErrorAction SilentlyContinue
    if (-not $vmhost -and $HostAddress.ContainsKey($name)) {
        $vmhost = Get-VMHost -Name $HostAddress[$name] -ErrorAction SilentlyContinue
    }
    if (-not $vmhost) {
        Write-Warning "Host $name is not in vCenter. It was skipped."
        continue
    }
    Set-HostCis -VMHost $vmhost -PlanName $name
}

Write-Step '3. Still manual'
Write-Host 'Secure Boot, TPM configuration encryption, iDRAC hardening, and the patch level are not set by this script.'
Write-Host 'Pass -SyslogHost once a collector exists. Until then, remote log shipping stays open.'
if (-not $Apply) {
    Write-Host ''
    Write-Host 'No changes were made. Apply with:  .\Set-SiicEsxiCisLevel1.ps1 -Apply' -ForegroundColor Cyan
}
Disconnect-VIServer -Server $VCenter -Confirm:$false
