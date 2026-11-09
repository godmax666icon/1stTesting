#Requires -Version 5.1
#Requires -Modules VMware.PowerCLI
<#
.SYNOPSIS
  Recreates the SiiC ESXi network and datastore layout after a fresh ESXi install.

.DESCRIPTION
  Built from VirtualNetworkSummary.xlsx (RVTools-style export) and the address sheet.
  Run it from a clean admin workstation that can reach vCenter. It does not store passwords.

  Preview, which is the default, connects and prints every change without making it:

      .\New-SiicEsxiConfig.ps1

  Apply the network and vCenter changes:

      .\New-SiicEsxiConfig.ps1 -Apply

  Create the two shared VMFS datastores only after the new PowerStore volumes are
  mapped and you have pasted their new NAA IDs into $SharedLuns below:

      .\New-SiicEsxiConfig.ps1 -Apply -FormatDatastoresConfirm FORMAT-NEW-LUNS

  Order of operations before this script:
    1. ESXi 8.0 Update 3k is installed on each R640.
    2. The DCUI management address is already set, so this script does not move vmk0.
    3. vCenter is deployed and reachable.
    4. Fibre Channel zoning to the new PowerStore volumes is in place.
    5. The old PowerStore volumes from the incident have been deleted. Their NAA IDs
       must not be reused.

  After this script, apply the CIS ESXi 8 Level 1 host baseline. That script does not
  enable lockdown mode:

      .\Set-SiicEsxiCisLevel1.ps1
      .\Set-SiicEsxiCisLevel1.ps1 -Apply

  What the export actually recorded
    Datacenter SiiC, cluster Cluster.
    Standard switches only. No distributed switch.
    vSwitch0  MTU 1500, vmnic0 + vmnic1 (10 Gb, PCI 0000:19:00.0 and 0000:19:00.1),
              reject promiscuous, MAC changes, and forged transmits.
    vSwitch1  MTU 1500, vmnic3 only (1 Gb, PCI 0000:01:00.1),
              reject promiscuous, accept MAC changes and forged transmits.
    vSwitchBMC  vusb0 only, same reject policy as vSwitch0. No VMkernel address was in the export.
    Unused on every host, so this script leaves them unused:
              vmnic2 (0000:01:00.0), vmnic4, vmnic5, vmnic6, vmnic7.
    Teaming on every switch: route based on originating virtual port, link status,
              notify switches, failback enabled.
    Shared VMFS: PS500T_datastore1 and PS500T_datastore2, 12,582,656 MiB each, all three hosts.
    Local VMFS: esxi1_datastore1, esxi2_datastore1, esxi3_datastore1, 326,144 MiB, one host each.

  What the export did not record, and the assumption this script uses
    Port group VLAN IDs were not in the file. The address sheet marked VLAN 12 as untagged,
    and the VM inventory uses port groups named "VLAN 12" and "DMZ".
    VLAN 12, Management, and vMotion are placed on the 10 Gb vSwitch0 with VLAN ID 0.
    DMZ is placed on vSwitch1 with VLAN ID 0, because that switch is a dedicated uplink
    on every host. If the physical port for PCI 0000:01:00.1 is a trunk, set
    $DmzVlanId to the tagged VLAN before you apply.
#>
[CmdletBinding()]
param(
    [string]$VCenter = 'vcenter.siic.local',
    [switch]$Apply,
    [string]$FormatDatastoresConfirm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Old DNS addresses 172.28.2.162 and 172.28.2.163 belong to HFM-11-2 and FDMEE-11-2,
# not to domain controllers. Point the hosts at DC01 once it is restored.
$DnsServers = @('172.28.2.141')
$DnsDomain = 'siic.local'
$Gateway = '172.28.2.254'
$SubnetMask = '255.255.255.0'
$NtpServer = 'stdtime.gov.hk'
$DatacenterName = 'SiiC'
$ClusterName = 'Cluster'

# 0 means untagged. Change $DmzVlanId only if vmnic3's switch port is a trunk.
$Vlan12VlanId = 0
$VMotionVlanId = 0
$DmzVlanId = 0

# Paste the NEW PowerStore NAA IDs here after the new volumes are mapped.
# Leave them blank to print candidate LUNs and format nothing.
# The incident volumes were:
#   PS500T_datastore1  naa.68ccf09800e2754238e1f6df453f14df
#   PS500T_datastore2  naa.68ccf09800fbbbc5123858a2eec14730
$SharedLuns = [ordered]@{
    'PS500T_datastore1' = ''
    'PS500T_datastore2' = ''
}

$HostPlan = @(
    [pscustomobject]@{ Name = 'esxi1.siic.local'; Ip = '172.28.2.191'; VMotion = '172.28.2.192'; LocalDatastore = 'esxi1_datastore1' }
    [pscustomobject]@{ Name = 'esxi2.siic.local'; Ip = '172.28.2.194'; VMotion = '172.28.2.195'; LocalDatastore = 'esxi2_datastore1' }
    [pscustomobject]@{ Name = 'esxi3.siic.local'; Ip = '172.28.2.197'; VMotion = '172.28.2.198'; LocalDatastore = 'esxi3_datastore1' }
)

# PCI addresses were the same vmnic names on all three R640s. Match PCI, not the
# vmnic number, in case a reinstall enumerates them differently.
$VSwitch0Pci = @('0000:19:00.0', '0000:19:00.1')
$VSwitch1Pci = @('0000:01:00.1')

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

function Get-PnicMap {
    param($VMHost)
    # Refresh the host view so PCI data is current.
    $view = Get-View -Id $VMHost.Id
    return @($view.Config.Network.Pnic)
}

function Resolve-Pnic {
    param($VMHost, [string[]]$PciAddresses)
    $pnics = Get-PnicMap -VMHost $VMHost
    $names = foreach ($pci in $PciAddresses) {
        $hit = @($pnics | Where-Object { $_.Pci -eq $pci -or $_.Pci -like "*:$pci" -or $_.Pci -like "*$pci" })
        if ($hit.Count -eq 0) {
            throw "Host $($VMHost.Name) has no physical NIC at PCI $pci."
        }
        if ($hit.Count -gt 1) {
            throw "Host $($VMHost.Name) PCI $pci matched more than one NIC: $($hit.Device -join ', ')."
        }
        $hit[0].Device
    }
    return @($names)
}

function Show-HostNics {
    param($VMHost)
    $pnics = Get-PnicMap -VMHost $VMHost
    Write-Host ("Host {0}" -f $VMHost.Name)
    foreach ($nic in ($pnics | Sort-Object Device)) {
        $link = if ($nic.LinkSpeed) { "$($nic.LinkSpeed.SpeedMb) Mb/s" } else { 'link down' }
        Write-Host ("  {0,-8} PCI {1,-14} MAC {2}  {3}  driver {4}" -f $nic.Device, $nic.Pci, $nic.Mac, $link, $nic.Driver)
    }
}

function Set-SwitchSecurity {
    param($VirtualSwitch, [bool]$MacChanges, [bool]$ForgedTransmits)
    $policy = Get-SecurityPolicy -VirtualSwitch $VirtualSwitch
    $needs = $policy.AllowPromiscuous -or ($policy.MacChanges -ne $MacChanges) -or ($policy.ForgedTransmits -ne $ForgedTransmits)
    $label = "security on $($VirtualSwitch.VMHost.Name) $($VirtualSwitch.Name): promiscuous Reject, MAC changes $MacChanges, forged transmits $ForgedTransmits"
    if (-not $needs) {
        Write-Host "KEEP    $label"
        return
    }
    if (Use-Change $label) {
        Set-SecurityPolicy -SecurityPolicy $policy -AllowPromiscuous $false -MacChanges:$MacChanges -ForgedTransmits:$ForgedTransmits | Out-Null
    }
}

function Set-SwitchTeaming {
    param($VirtualSwitch)
    $policy = Get-NicTeamingPolicy -VirtualSwitch $VirtualSwitch
    $label = "teaming on $($VirtualSwitch.VMHost.Name) $($VirtualSwitch.Name): originating port, link status, notify, failback"
    $ok = $policy.LoadBalancingPolicy -eq 'LoadBalanceSrcId' -and
        $policy.NetworkFailoverDetectionPolicy -eq 'LinkStatus' -and
        $policy.NotifySwitches -and $policy.FailbackEnabled
    if ($ok) {
        Write-Host "KEEP    $label"
        return
    }
    if (Use-Change $label) {
        Set-NicTeamingPolicy -VirtualSwitchPolicy $policy `
            -LoadBalancingPolicy LoadBalanceSrcId `
            -NetworkFailoverDetectionPolicy LinkStatus `
            -NotifySwitches $true `
            -FailbackEnabled $true | Out-Null
    }
}

function Ensure-StandardSwitch {
    param($VMHost, [string]$Name, [string[]]$NicNames, [int]$Mtu = 1500)
    $existing = Get-VirtualSwitch -VMHost $VMHost -Name $Name -Standard -ErrorAction SilentlyContinue
    $nicList = $NicNames -join ', '
    if (-not $existing) {
        if (Use-Change "create $Name on $($VMHost.Name) with $nicList, MTU $Mtu") {
            return New-VirtualSwitch -VMHost $VMHost -Name $Name -Nic $NicNames -Mtu $Mtu -Confirm:$false
        }
        return $null
    }
    $current = @($existing.Nic) | Sort-Object
    $wanted = @($NicNames) | Sort-Object
    $sameNics = ($current -join ',') -eq ($wanted -join ',')
    $sameMtu = $existing.Mtu -eq $Mtu
    if ($sameNics -and $sameMtu) {
        Write-Host "KEEP    $Name on $($VMHost.Name) uplinks $nicList"
        return $existing
    }
    if (Use-Change "set $Name on $($VMHost.Name) uplinks to $nicList, MTU $Mtu") {
        return Set-VirtualSwitch -VirtualSwitch $existing -Nic $NicNames -Mtu $Mtu -Confirm:$false
    }
    return $existing
}

function Ensure-PortGroup {
    param($VMHost, [string]$SwitchName, [string]$Name, [int]$VlanId)
    $switch = Get-VirtualSwitch -VMHost $VMHost -Name $SwitchName -Standard -ErrorAction SilentlyContinue
    if (-not $switch) {
        Write-Warning "Skip port group $Name. $SwitchName does not exist on $($VMHost.Name) yet."
        return
    }
    $pg = Get-VirtualPortGroup -VMHost $VMHost -Name $Name -Standard -ErrorAction SilentlyContinue |
        Where-Object { $_.VirtualSwitchName -eq $SwitchName }
    if (-not $pg) {
        if (Use-Change "create port group '$Name' on $($VMHost.Name) $SwitchName VLAN $VlanId") {
            New-VirtualPortGroup -VirtualSwitch $switch -Name $Name -VLanId $VlanId -Confirm:$false | Out-Null
        }
        return
    }
    if ([int]$pg.VLanId -eq $VlanId) {
        Write-Host "KEEP    port group '$Name' on $($VMHost.Name) $SwitchName VLAN $VlanId"
        return
    }
    if (Use-Change "set port group '$Name' on $($VMHost.Name) VLAN from $($pg.VLanId) to $VlanId") {
        Set-VirtualPortGroup -VirtualPortGroup $pg -VLanId $VlanId -Confirm:$false | Out-Null
    }
}

function Ensure-VMotionAdapter {
    param($VMHost, [string]$IpAddress)
    $existing = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -ErrorAction SilentlyContinue |
        Where-Object { $_.IP -eq $IpAddress }
    if ($existing) {
        if (-not $existing.VMotionEnabled -and (Use-Change "enable vMotion on $($VMHost.Name) $($existing.Name) $IpAddress")) {
            Set-VMHostNetworkAdapter -VirtualNic $existing -VMotionEnabled $true -Confirm:$false | Out-Null
        }
        else {
            Write-Host "KEEP    vMotion $($VMHost.Name) $IpAddress on $($existing.Name)"
        }
        return
    }
    $switch = Get-VirtualSwitch -VMHost $VMHost -Name 'vSwitch0' -Standard -ErrorAction SilentlyContinue
    if (-not $switch) {
        Write-Warning "Skip vMotion on $($VMHost.Name). vSwitch0 is not present."
        return
    }
    if (Use-Change "add vMotion vmk $($VMHost.Name) $IpAddress on vSwitch0 port group vMotion") {
        New-VMHostNetworkAdapter -VMHost $VMHost -VirtualSwitch $switch -PortGroup 'vMotion' `
            -IP $IpAddress -SubnetMask $SubnetMask -VMotionEnabled $true `
            -ManagementTrafficEnabled $false -Mtu 1500 -Confirm:$false | Out-Null
    }
}

function Ensure-HostIdentity {
    param($VMHost)
    $network = Get-VMHostNetwork -VMHost $VMHost
    $dnsNow = @($network.DnsAddress) -join ', '
    $dnsWant = $DnsServers -join ', '
    $label = "DNS $($VMHost.Name): $dnsWant, domain $DnsDomain, gateway $Gateway. Current DNS: $dnsNow"
    $same = ($dnsNow -eq $dnsWant) -and ($network.DomainName -eq $DnsDomain) -and ($network.VMKernelGateway -eq $Gateway)
    if ($same) {
        Write-Host "KEEP    $label"
    }
    elseif (Use-Change $label) {
        Set-VMHostNetwork -Network $network -DomainName $DnsDomain -SearchDomain $DnsDomain `
            -DnsAddress $DnsServers -VMKernelGateway $Gateway -Confirm:$false | Out-Null
    }

    $ntp = @(Get-VMHostNtpServer -VMHost $VMHost -ErrorAction SilentlyContinue)
    $service = Get-VMHostService -VMHost $VMHost | Where-Object { $_.Key -eq 'ntpd' }
    if ($ntp -contains $NtpServer -and $service.Running -and $service.Policy -eq 'On') {
        Write-Host "KEEP    NTP $($VMHost.Name) $NtpServer"
    }
    elseif (Use-Change "set NTP $NtpServer on $($VMHost.Name) and start ntpd") {
        if ($ntp -notcontains $NtpServer) {
            Add-VMHostNtpServer -VMHost $VMHost -NtpServer $NtpServer -Confirm:$false | Out-Null
        }
        Set-VMHostService -HostService $service -Policy On -Confirm:$false | Out-Null
        if ($service.Running) {
            Restart-VMHostService -HostService $service -Confirm:$false | Out-Null
        }
        else {
            Start-VMHostService -HostService $service -Confirm:$false | Out-Null
        }
    }
}

function Rename-LocalDatastore {
    param($VMHost, [string]$ExpectedName)
    $existing = Get-Datastore -VMHost $VMHost -Name $ExpectedName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "KEEP    local datastore $ExpectedName on $($VMHost.Name)"
        return
    }
    $localLuns = @(Get-ScsiLun -VMHost $VMHost -LunType disk -ErrorAction SilentlyContinue | Where-Object { $_.IsLocal })
    $localNames = @($localLuns | ForEach-Object { $_.CanonicalName })
    $candidates = @(Get-Datastore -VMHost $VMHost -ErrorAction SilentlyContinue | Where-Object {
            $_.Type -eq 'VMFS' -and -not $_.ExtensionData.Summary.MultipleHostAccess -and
            @($_.ExtensionData.Info.Vmfs.Extent | ForEach-Object { $_.DiskName }) | Where-Object { $localNames -contains $_ }
        })
    if ($candidates.Count -eq 1) {
        if (Use-Change "rename local datastore '$($candidates[0].Name)' to $ExpectedName on $($VMHost.Name)") {
            Set-Datastore -Datastore $candidates[0] -Name $ExpectedName -Confirm:$false | Out-Null
        }
        return
    }
    Write-Warning "Local datastore $ExpectedName was not found on $($VMHost.Name), and there is not exactly one local VMFS to rename. No local disk will be formatted."
}

function Show-SharedLunCandidates {
    param($VMHost)
    Write-Host "Shared LUN candidates on $($VMHost.Name) (not local, larger than 1 TB):"
    $luns = @(Get-ScsiLun -VMHost $VMHost -LunType disk | Where-Object { -not $_.IsLocal -and $_.CapacityGB -gt 1000 })
    if ($luns.Count -eq 0) {
        Write-Warning "No shared LUN larger than 1 TB is visible. Check zoning and PowerStore host mapping, then rescan."
        return
    }
    foreach ($lun in $luns) {
        Write-Host ("  {0,-50} {1,8:N0} GB  {2} {3}" -f $lun.CanonicalName, [math]::Round($lun.CapacityGB), $lun.Vendor, $lun.Model)
    }
}

function Ensure-SharedDatastore {
    param($VMHost, [string]$Name, [string]$Naa)
    $existing = Get-Datastore -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "KEEP    datastore $Name"
        return
    }
    if ([string]::IsNullOrWhiteSpace($Naa)) {
        Write-Warning "Datastore $Name has no NAA in `$SharedLuns. It was not created."
        return
    }
    $canonical = $Naa.Trim()
    if ($canonical -notlike 'naa.*') { $canonical = "naa.$canonical" }
    $retired = @(
        'naa.68ccf09800e2754238e1f6df453f14df',
        'naa.68ccf09800fbbbc5123858a2eec14730'
    )
    if ($retired -contains $canonical) {
        throw "Refusing $canonical for $Name. That NAA is from the incident export. Paste the NAA of the new PowerStore volume."
    }
    $lun = Get-ScsiLun -VMHost $VMHost -CanonicalName $canonical -ErrorAction SilentlyContinue
    if (-not $lun) {
        throw "Host $($VMHost.Name) cannot see $canonical for $Name. Rescan and check the PowerStore mapping before formatting."
    }
    if ($lun.IsLocal) {
        throw "$canonical is a local disk. Refusing to format it as $Name."
    }
    $confirm = "create VMFS 6 datastore $Name on $($VMHost.Name) $canonical ($([math]::Round($lun.CapacityGB)) GB)"
    if ($FormatDatastoresConfirm -ne 'FORMAT-NEW-LUNS') {
        Write-Warning "PLAN ONLY  $confirm. Re-run with -Apply -FormatDatastoresConfirm FORMAT-NEW-LUNS to format this LUN."
        return
    }
    if (Use-Change $confirm) {
        New-Datastore -VMHost $VMHost -Name $Name -Path $canonical -Vmfs -FileSystemVersion 6 -Confirm:$false | Out-Null
    }
}

# --- run -------------------------------------------------------------------

Write-Step '1. Connect to vCenter'
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope Session | Out-Null
$vcCred = Get-Credential -Message "vCenter administrator for $VCenter"
Connect-VIServer -Server $VCenter -Credential $vcCred | Out-Null
if (-not $Apply) {
    Write-Host 'Preview only. Re-run with -Apply to change vCenter, switches, and VMkernel ports.' -ForegroundColor Cyan
}

Write-Step '2. Datacenter and cluster'
$dc = Get-Datacenter -Name $DatacenterName -ErrorAction SilentlyContinue
if (-not $dc) {
    if (Use-Change "create datacenter $DatacenterName") {
        $dc = New-Datacenter -Name $DatacenterName -Location (Get-Folder -NoRecursion) -Confirm:$false
    }
}
else {
    Write-Host "KEEP    datacenter $DatacenterName"
}
$cluster = $null
if ($dc) {
    $cluster = Get-Cluster -Name $ClusterName -Location $dc -ErrorAction SilentlyContinue
    if (-not $cluster) {
        if (Use-Change "create cluster $ClusterName with HA on and DRS off") {
            $cluster = New-Cluster -Name $ClusterName -Location $dc -HAEnabled $true -DrsEnabled $false -Confirm:$false
        }
    }
    else {
        Write-Host "KEEP    cluster $ClusterName"
    }
}

Write-Step '3. Add the three hosts'
if (-not $cluster) {
    Write-Warning 'Cluster is not present. Host add and host configuration are skipped until the cluster exists.'
}
else {
    $hostCred = $null
    foreach ($plan in $HostPlan) {
        $already = Get-VMHost -Name $plan.Ip -ErrorAction SilentlyContinue
        if (-not $already) { $already = Get-VMHost -Name $plan.Name -ErrorAction SilentlyContinue }
        if ($already) {
            Write-Host "KEEP    host $($plan.Name) ($($plan.Ip)) is already in vCenter as $($already.Name)"
            continue
        }
        if (-not $hostCred) {
            $hostCred = Get-Credential -UserName 'root' -Message 'ESXi root. Used only to add hosts that are not in vCenter yet.'
        }
        if (Use-Change "add host $($plan.Ip) ($($plan.Name)) to $ClusterName") {
            Add-VMHost -Name $plan.Ip -Location $cluster -Credential $hostCred -Force -Confirm:$false | Out-Null
        }
    }
}

Write-Step '4. Physical NIC check'
$resolved = @()
foreach ($plan in $HostPlan) {
    $vmhost = Get-VMHost -Name $plan.Ip -ErrorAction SilentlyContinue
    if (-not $vmhost) { $vmhost = Get-VMHost -Name $plan.Name -ErrorAction SilentlyContinue }
    if (-not $vmhost) {
        Write-Warning "Host $($plan.Name) is not in vCenter. Networking for it is skipped."
        continue
    }
    Show-HostNics -VMHost $vmhost
    $v0 = Resolve-Pnic -VMHost $vmhost -PciAddresses $VSwitch0Pci
    $v1 = Resolve-Pnic -VMHost $vmhost -PciAddresses $VSwitch1Pci
    Write-Host ("  vSwitch0 NICs from PCI: {0}" -f ($v0 -join ', '))
    Write-Host ("  vSwitch1 NICs from PCI: {0}" -f ($v1 -join ', '))
    $resolved += [pscustomobject]@{ Plan = $plan; VMHost = $vmhost; V0 = $v0; V1 = $v1 }
}

Write-Step '5. Standard switches, teaming, and security'
foreach ($item in $resolved) {
    $vmhost = $item.VMHost
    $sw0 = Ensure-StandardSwitch -VMHost $vmhost -Name 'vSwitch0' -NicNames $item.V0
    if ($sw0) {
        Set-SwitchSecurity -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name 'vSwitch0' -Standard) -MacChanges $false -ForgedTransmits $false
        Set-SwitchTeaming -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name 'vSwitch0' -Standard)
    }
    $sw1 = Ensure-StandardSwitch -VMHost $vmhost -Name 'vSwitch1' -NicNames $item.V1
    if ($sw1) {
        Set-SwitchSecurity -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name 'vSwitch1' -Standard) -MacChanges $true -ForgedTransmits $true
        Set-SwitchTeaming -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name 'vSwitch1' -Standard)
    }

    $usb = @(Get-PnicMap -VMHost $vmhost | Where-Object { $_.Device -eq 'vusb0' })
    if ($usb.Count -eq 0) {
        Write-Warning "vusb0 is not present on $($vmhost.Name). vSwitchBMC was not created. Enable the iDRAC USB NIC, install Dell iSM, and run this script again."
    }
    else {
        $bmc = Ensure-StandardSwitch -VMHost $vmhost -Name 'vSwitchBMC' -NicNames @('vusb0')
        if ($bmc) {
            Set-SwitchSecurity -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name 'vSwitchBMC' -Standard) -MacChanges $false -ForgedTransmits $false
            Set-SwitchTeaming -VirtualSwitch (Get-VirtualSwitch -VMHost $vmhost -Name 'vSwitchBMC' -Standard)
        }
    }
}

Write-Step '6. Port groups VLAN 12, vMotion, and DMZ'
foreach ($item in $resolved) {
    Ensure-PortGroup -VMHost $item.VMHost -SwitchName 'vSwitch0' -Name 'VLAN 12' -VlanId $Vlan12VlanId
    Ensure-PortGroup -VMHost $item.VMHost -SwitchName 'vSwitch0' -Name 'vMotion' -VlanId $VMotionVlanId
    Ensure-PortGroup -VMHost $item.VMHost -SwitchName 'vSwitch1' -Name 'DMZ' -VlanId $DmzVlanId
}

Write-Step '7. vMotion VMkernel'
foreach ($item in $resolved) {
    $mgmt = Get-VMHostNetworkAdapter -VMHost $item.VMHost -VMKernel -ErrorAction SilentlyContinue |
        Where-Object { $_.IP -eq $item.Plan.Ip }
    if (-not $mgmt) {
        Write-Warning "vmk0 on $($item.VMHost.Name) is not $($item.Plan.Ip). Leave the DCUI management address as it is. This script will not change it."
    }
    else {
        Write-Host "KEEP    management $($item.Plan.Name) $($item.Plan.Ip) on $($mgmt.Name)"
    }
    Ensure-VMotionAdapter -VMHost $item.VMHost -IpAddress $item.Plan.VMotion
}

Write-Step '8. DNS, gateway, and NTP'
foreach ($item in $resolved) {
    Ensure-HostIdentity -VMHost $item.VMHost
}

Write-Step '9. Datastores'
$first = $resolved | Select-Object -First 1
if (-not $first) {
    Write-Warning 'No host is available for a storage rescan.'
}
else {
    if (Use-Change "rescan HBA and VMFS on $($first.VMHost.Name)") {
        Get-VMHostStorage -VMHost $first.VMHost -RescanAllHba | Out-Null
        Get-VMHostStorage -VMHost $first.VMHost -RescanVmfs | Out-Null
    }
    Show-SharedLunCandidates -VMHost $first.VMHost
    foreach ($name in @($SharedLuns.Keys)) {
        Ensure-SharedDatastore -VMHost $first.VMHost -Name $name -Naa $SharedLuns[$name]
    }
    if ($Apply) {
        foreach ($item in $resolved) {
            Get-VMHostStorage -VMHost $item.VMHost -RescanVmfs | Out-Null
        }
    }
}
foreach ($item in $resolved) {
    Rename-LocalDatastore -VMHost $item.VMHost -ExpectedName $item.Plan.LocalDatastore
}

Write-Step '10. Result'
foreach ($item in $resolved) {
    Write-Host ''
    Write-Host $item.VMHost.Name -ForegroundColor Green
    Get-VirtualSwitch -VMHost $item.VMHost -Standard | ForEach-Object {
        $sec = Get-SecurityPolicy -VirtualSwitch $_
        Write-Host ("  {0}  MTU {1}  uplinks {2}  MAC changes {3}  forged {4}" -f $_.Name, $_.Mtu, ($_.Nic -join ','), $sec.MacChanges, $sec.ForgedTransmits)
    }
    Get-VirtualPortGroup -VMHost $item.VMHost -Standard | ForEach-Object {
        Write-Host ("  port group {0,-18} switch {1,-12} VLAN {2}" -f $_.Name, $_.VirtualSwitchName, $_.VLanId)
    }
    Get-VMHostNetworkAdapter -VMHost $item.VMHost -VMKernel | ForEach-Object {
        Write-Host ("  {0,-6} {1,-16} vMotion {2}" -f $_.Name, $_.IP, $_.VMotionEnabled)
    }
}
Get-Datastore | Sort-Object Name | ForEach-Object {
    Write-Host ("  datastore {0,-22} {1,8:N0} GB  {2}" -f $_.Name, [math]::Round($_.CapacityGB), $_.Type)
}

if (-not $Apply) {
    Write-Host ''
    Write-Host 'No changes were made. Apply with:  .\New-SiicEsxiConfig.ps1 -Apply' -ForegroundColor Cyan
}
Disconnect-VIServer -Server $VCenter -Confirm:$false
