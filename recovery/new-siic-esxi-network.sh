#!/bin/sh
# Recreate the SiiC standard-switch network on one ESXi host.
# Run this on the host shell when vCenter is not available.
# It does not change the vmk0 management address.
#
# Copy it to the host, then preview and apply:
#   scp recovery/new-siic-esxi-network.sh root@172.28.2.191:/tmp/
#   ssh root@172.28.2.191
#   sh /tmp/new-siic-esxi-network.sh
#   sh /tmp/new-siic-esxi-network.sh apply
#
# Turn SSH off again after the three hosts are done.
#
# What it builds, from VirtualNetworkSummary.xlsx and the address sheet:
#   vSwitch0    MTU 1500, PCI 0000:19:00.0 and 0000:19:00.1
#               reject promiscuous, MAC changes, and forged transmits
#               the existing vmk0 port group, "VLAN 12", and "vMotion", VLAN 0
#   vSwitch1    MTU 1500, PCI 0000:01:00.1
#               reject promiscuous, accept MAC changes and forged transmits
#               port group "DMZ", VLAN 0
#   vSwitchBMC  vusb0 only, when that NIC exists. No VMkernel address.
#   teaming     originating port, link status, notify switches, failback
#   vMotion     a new vmk on port group vMotion. vmk0 is not moved.
#               172.28.2.191 -> 172.28.2.192
#               172.28.2.194 -> 172.28.2.195
#               172.28.2.197 -> 172.28.2.198
#   DNS         172.28.2.141, search siic.local
#   gateway     172.28.2.254, only if the default route is missing
#   NTP         stdtime.gov.hk
#
# vmnic2 (0000:01:00.0), vmnic4, vmnic5, vmnic6, and vmnic7 stay unused.
# Change DMZ_VLAN only if the 1G switch port is a trunk. 0 means untagged.

DMZ_VLAN=0
GATEWAY=172.28.2.254
DNS=172.28.2.141
DOMAIN=siic.local
NTP=stdtime.gov.hk
MASK=255.255.255.0

MODE=plan
if [ "$1" = apply ]; then
    MODE=apply
fi

say() {
    printf '%s\n' "$1"
}

run() {
    if [ "$MODE" = apply ]; then
        say "APPLY   $*"
        "$@" || die "Command failed: $*"
    else
        say "PLAN    $*"
    fi
}

die() {
    say "STOP    $1"
    exit 1
}

nic_for_pci() {
    esxcli network nic list | awk -v pci="$1" '$2 == pci { print $1; found = 1; exit } END { exit !found }'
}

uplinks_of() {
    esxcli network vswitch standard list -v "$1" 2>/dev/null | sed -n 's/^ *Uplinks: *//p'
}

has_uplink() {
    list=$(uplinks_of "$1" | tr ',' ' ')
    for item in $list; do
        if [ "$item" = "$2" ]; then
            return 0
        fi
    done
    return 1
}

owner_of() {
    esxcli network vswitch standard list | awk -v nic="$1" '
        /^[^[:space:]]/ { sw = $1 }
        /Uplinks:/ {
            line = $0
            sub(/^.*Uplinks: */, "", line)
            n = split(line, a, /[, ]+/)
            for (i = 1; i <= n; i++) if (a[i] == nic) { print sw; exit }
        }
    '
}

switch_exists() {
    esxcli network vswitch standard list | awk -v sw="$1" '$1 == sw { found = 1; exit } END { exit !found }'
}

portgroup_exists() {
    esxcli network vswitch standard portgroup list | grep -F "$1" | grep -F "$2" >/dev/null 2>&1
}

ensure_switch() {
    if switch_exists "$1"; then
        say "KEEP    switch $1"
    else
        run esxcli network vswitch standard add -v "$1"
    fi
    run esxcli network vswitch standard set -v "$1" -m 1500
    run esxcli network vswitch standard policy security set -v "$1" \
        --allow-promiscuous=false --allow-mac-change="$2" --allow-forged-transmits="$3"
    run esxcli network vswitch standard policy failover set -v "$1" \
        --load-balancing=portid --failure-detection=link --notify-switches=true --failback=true
}

ensure_uplink() {
    owner=$(owner_of "$2")
    if [ -n "$owner" ] && [ "$owner" != "$1" ]; then
        die "$2 is already an uplink of $owner. It was not moved."
    fi
    if has_uplink "$1" "$2"; then
        say "KEEP    $1 uplink $2"
    else
        run esxcli network vswitch standard uplink add -v "$1" -u "$2"
    fi
}

ensure_portgroup() {
    if portgroup_exists "$1" "$2"; then
        say "KEEP    port group $1 on $2"
    elif esxcli network vswitch standard portgroup list | grep -F "$1" >/dev/null 2>&1; then
        die "Port group $1 exists on another switch. It was not moved."
    else
        run esxcli network vswitch standard portgroup add -p "$1" -v "$2"
    fi
    run esxcli network vswitch standard portgroup set -p "$1" --vlan-id "$3"
    run esxcli network vswitch standard portgroup policy security set -p "$1" \
        --allow-promiscuous=false --allow-mac-change="$4" --allow-forged-transmits="$5"
    run esxcli network vswitch standard portgroup policy failover set -p "$1" \
        --load-balancing=portid --failure-detection=link --notify-switches=true --failback=true
}

say "== 1. Read vmk0 and choose this host"
vmk0_ip=$(esxcli network ip interface ipv4 get -i vmk0 | awk '$1 == "vmk0" { print $2; exit }')
vmk0_switch=$(esxcli network ip interface list | awk '
    /^vmk0$/ { grab = 1; next }
    grab && /^[^ ]/ { exit }
    grab && /Portset:/ { sub(/^.*Portset: */, ""); print; exit }
')
vmk0_pg=$(esxcli network ip interface list | awk '
    /^vmk0$/ { grab = 1; next }
    grab && /^[^ ]/ { exit }
    grab && /Portgroup:/ { sub(/^.*Portgroup: */, ""); print; exit }
')
case "$vmk0_ip" in
    172.28.2.191) short=esxi1; vmotion=172.28.2.192 ;;
    172.28.2.194) short=esxi2; vmotion=172.28.2.195 ;;
    172.28.2.197) short=esxi3; vmotion=172.28.2.198 ;;
    *) die "vmk0 address is '$vmk0_ip', not 172.28.2.191, .194, or .197. vmk0 was not changed." ;;
esac
if [ "$vmk0_switch" != "vSwitch0" ]; then
    die "vmk0 is on '$vmk0_switch', not vSwitch0. vmk0 was not changed."
fi
if [ -z "$vmk0_pg" ]; then
    die "vmk0 has no port group. vmk0 was not changed."
fi
say "KEEP    $short vmk0 $vmk0_ip on $vmk0_pg / vSwitch0. vMotion will be $vmotion."
if [ "$MODE" = plan ]; then
    say "Preview only. Re-run with:  sh /tmp/new-siic-esxi-network.sh apply"
fi

say "== 2. Resolve uplinks by PCI address"
nic0=$(nic_for_pci "0000:19:00.0") || die "No NIC at PCI 0000:19:00.0."
nic1=$(nic_for_pci "0000:19:00.1") || die "No NIC at PCI 0000:19:00.1."
nic_dmz=$(nic_for_pci "0000:01:00.1") || die "No NIC at PCI 0000:01:00.1."
say "KEEP    vSwitch0 NICs $nic0 and $nic1. vSwitch1 NIC $nic_dmz."

current=$(uplinks_of vSwitch0 | tr ',' ' ')
for item in $current; do
    if [ "$item" != "$nic0" ] && [ "$item" != "$nic1" ]; then
        die "vSwitch0 uplink $item is not $nic0 or $nic1. vmk0 was not changed."
    fi
done

say "== 3. vSwitch0, management, VLAN 12, and vMotion"
ensure_uplink vSwitch0 "$nic0"
ensure_uplink vSwitch0 "$nic1"
ensure_switch vSwitch0 false false
ensure_portgroup "$vmk0_pg" vSwitch0 0 false false
ensure_portgroup "VLAN 12" vSwitch0 0 false false
ensure_portgroup "vMotion" vSwitch0 0 false false

say "== 4. vSwitch1 and DMZ"
ensure_switch vSwitch1 true true
ensure_uplink vSwitch1 "$nic_dmz"
ensure_portgroup "DMZ" vSwitch1 "$DMZ_VLAN" true true

say "== 5. vSwitchBMC"
if esxcli network nic list | awk '$1 == "vusb0" { found = 1 } END { exit !found }'; then
    owner=$(owner_of vusb0)
    if [ -n "$owner" ] && [ "$owner" != "vSwitchBMC" ]; then
        die "vusb0 is already an uplink of $owner. It was not moved."
    fi
    ensure_switch vSwitchBMC false false
    ensure_uplink vSwitchBMC vusb0
else
    say "SKIP    vusb0 is not present. vSwitchBMC was not created."
fi

say "== 6. vMotion VMkernel"
vmk_move=$(esxcli network ip interface ipv4 get | awk -v ip="$vmotion" '$2 == ip { print $1; exit }')
if [ -n "$vmk_move" ]; then
    if [ "$vmk_move" = "vmk0" ]; then
        die "The vMotion address is on vmk0. vmk0 was not changed."
    fi
    say "KEEP    vMotion address $vmotion is already on $vmk_move"
    if esxcli network ip interface tag get -i "$vmk_move" 2>/dev/null | grep -q VMotion; then
        say "KEEP    $vmk_move VMotion tag"
    else
        run esxcli network ip interface tag add -i "$vmk_move" -t VMotion
    fi
else
    vmk_move=""
    for n in 1 2 3 4 5 6 7 8 9; do
        if ! esxcli network ip interface list | awk -v name="vmk$n" '$1 == name { found = 1 } END { exit !found }'; then
            vmk_move="vmk$n"
            break
        fi
    done
    if [ -z "$vmk_move" ]; then
        die "No free vmk name between vmk1 and vmk9."
    fi
    run esxcli network ip interface add -i "$vmk_move" -p vMotion -m 1500
    run esxcli network ip interface ipv4 set -i "$vmk_move" -t static -I "$vmotion" -N "$MASK"
    run esxcli network ip interface tag add -i "$vmk_move" -t VMotion
fi

say "== 7. Gateway, DNS, hostname, and NTP"
gw=$(esxcli network ip route ipv4 list | awk '$1 == "default" || $1 == "0.0.0.0" { print $3; exit }')
if [ "$gw" = "$GATEWAY" ]; then
    say "KEEP    default gateway $GATEWAY"
elif [ -z "$gw" ]; then
    run esxcli network ip route ipv4 add -n default -g "$GATEWAY"
else
    die "Default gateway is $gw, not $GATEWAY. vmk0 was not changed."
fi

if esxcli network ip dns server list | grep -F "$DNS" >/dev/null 2>&1; then
    say "KEEP    DNS server $DNS"
else
    run esxcli network ip dns server add -s "$DNS"
fi
for old in 172.28.2.162 172.28.2.163; do
    if esxcli network ip dns server list | grep -F "$old" >/dev/null 2>&1; then
        run esxcli network ip dns server remove -s "$old"
    fi
done
if esxcli network ip dns search list | grep -F "$DOMAIN" >/dev/null 2>&1; then
    say "KEEP    DNS search $DOMAIN"
else
    run esxcli network ip dns search add -d "$DOMAIN"
fi
run esxcli system hostname set --host="$short" --domain="$DOMAIN"

if esxcli system ntp get | grep -F "$NTP" >/dev/null 2>&1; then
    say "KEEP    NTP server $NTP is listed"
else
    run esxcli system ntp set --server="$NTP"
fi
run esxcli system ntp set --enabled=true
run /etc/init.d/ntpd start
run chkconfig ntpd on

say "== 8. Result"
say "vmk0 $vmk0_ip was not modified."
esxcli network vswitch standard list
esxcli network vswitch standard portgroup list
esxcli network ip interface ipv4 get
if [ "$MODE" != apply ]; then
    say "No changes were made. Apply with:  sh /tmp/new-siic-esxi-network.sh apply"
fi
