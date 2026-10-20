$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

public static class AclProbe {
    [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct Request {
        public uint DesiredAccess; public IntPtr PrincipalSelfSid; public IntPtr ObjectTypeList;
        public uint ObjectTypeListLength; public IntPtr OptionalArguments;
    }
    [StructLayout(LayoutKind.Sequential)] struct Reply {
        public uint ResultListLength; public IntPtr GrantedAccessMask;
        public IntPtr SaclEvaluationResults; public IntPtr Error;
    }
    [DllImport("authz.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool AuthzInitializeResourceManager(uint flags, IntPtr access, IntPtr groups, IntPtr free, string name, out IntPtr rm);
    [DllImport("authz.dll", SetLastError=true)]
    static extern bool AuthzInitializeContextFromSid(uint flags, IntPtr sid, IntPtr rm, IntPtr expires, Luid id, IntPtr args, out IntPtr context);
    [DllImport("authz.dll", SetLastError=true)]
    static extern bool AuthzAddSidsToContext(IntPtr context, [In] SidAndAttributes[] groups, uint count, IntPtr restricted, uint restrictedCount, out IntPtr result);
    [DllImport("authz.dll", SetLastError=true)]
    static extern bool AuthzAccessCheck(uint flags, IntPtr context, ref Request request, IntPtr audit, byte[] sd, IntPtr optionalSd, uint optionalCount, ref Reply reply, IntPtr results);
    [DllImport("authz.dll")] static extern bool AuthzFreeContext(IntPtr context);
    [DllImport("authz.dll")] static extern bool AuthzFreeResourceManager(IntPtr rm);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint GetSystemDirectory(System.Text.StringBuilder buffer, uint size);
    static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static IntPtr Sid(string value) {
        var sid = new SecurityIdentifier(value); var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
        var p = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, p, bytes.Length); return p;
    }
    static uint Map(uint mask) {
        uint value = mask & 0x0fffffff;
        if ((mask & 0x80000000) != 0) value |= 0x120089;
        if ((mask & 0x40000000) != 0) value |= 0x120116;
        if ((mask & 0x20000000) != 0) value |= 0x1200a0;
        if ((mask & 0x10000000) != 0) value |= 0x1f01ff;
        return value;
    }
    public static Dictionary<string, object> StandardGroupAccess(byte[] descriptor, string[] groupSids) {
        IntPtr rm=IntPtr.Zero, context=IntPtr.Zero, expanded=IntPtr.Zero;
        var allocations = new List<IntPtr>();
        try {
            Check(AuthzInitializeResourceManager(1, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, "Read-only Windows lab ACL probe", out rm));
            var user = Sid("S-1-5-21-4294967290-4294967290-4294967290-1001"); allocations.Add(user);
            Check(AuthzInitializeContextFromSid(2, user, rm, IntPtr.Zero, new Luid(), IntPtr.Zero, out context));
            var groups = new SidAndAttributes[groupSids.Length];
            for (int i=0; i<groups.Length; i++) {
                var p=Sid(groupSids[i]); allocations.Add(p); groups[i]=new SidAndAttributes { Sid=p, Attributes=4 };
            }
            Check(AuthzAddSidsToContext(context, groups, (uint)groups.Length, IntPtr.Zero, 0, out expanded));
            var raw = new RawSecurityDescriptor(descriptor, 0);
            if (raw.DiscretionaryAcl != null) foreach (GenericAce ace in raw.DiscretionaryAcl) {
                var known = ace as KnownAce;
                if (known != null) known.AccessMask = unchecked((int)Map(unchecked((uint)known.AccessMask)));
            }
            var mapped = new byte[raw.BinaryLength]; raw.GetBinaryForm(mapped, 0);
            var granted=Marshal.AllocHGlobal(4); allocations.Add(granted); Marshal.WriteInt32(granted, 0);
            var error=Marshal.AllocHGlobal(4); allocations.Add(error); Marshal.WriteInt32(error, 0);
            var sacl=Marshal.AllocHGlobal(4); allocations.Add(sacl); Marshal.WriteInt32(sacl, 0);
            var request = new Request { DesiredAccess=0x02000000 };
            var reply = new Reply { ResultListLength=1, GrantedAccessMask=granted, Error=error, SaclEvaluationResults=sacl };
            Check(AuthzAccessCheck(0, expanded, ref request, IntPtr.Zero, mapped, IntPtr.Zero, 0, ref reply, IntPtr.Zero));
            uint rights = unchecked((uint)Marshal.ReadInt32(granted));
            return new Dictionary<string, object> {
                {"access_check_error", Marshal.ReadInt32(error)}, {"granted_mask", "0x"+rights.ToString("X8")},
                {"write_data_or_add_file", (rights & 2) != 0}, {"append_data_or_add_subdirectory", (rights & 4) != 0},
                {"delete_child", (rights & 0x40) != 0}, {"delete", (rights & 0x10000) != 0},
                {"write_dacl", (rights & 0x40000) != 0}, {"write_owner", (rights & 0x80000) != 0},
                {"read_execute", (rights & 0x1200a9) == 0x1200a9}
            };
        } finally {
            if (expanded != IntPtr.Zero) AuthzFreeContext(expanded);
            if (context != IntPtr.Zero) AuthzFreeContext(context);
            if (rm != IntPtr.Zero) AuthzFreeResourceManager(rm);
            foreach (var p in allocations) Marshal.FreeHGlobal(p);
        }
    }
}
'@
$buffer = [Text.StringBuilder]::new(32768)
$length = [AclProbe]::GetSystemDirectory($buffer, [uint32]$buffer.Capacity)
if ($length -eq 0 -or $length -ge $buffer.Capacity) { throw 'GetSystemDirectory failed' }
$volume = [IO.Path]::GetPathRoot($buffer.ToString())
$groupSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-2-0', 'S-1-5-113')
$paths = @(
    $volume,
    (Join-Path $volume 'tools'),
    (Join-Path $volume 'tools\zstd'),
    (Join-Path $volume 'tools\zstd\zstd.exe'),
    (Join-Path $volume 'Program Files'),
    (Join-Path $volume 'Program Files\Git'),
    (Join-Path $volume 'Program Files\Git\usr'),
    (Join-Path $volume 'Program Files\Git\usr\bin'),
    (Join-Path $volume 'Program Files\Git\usr\bin\tar.exe')
)
$results = foreach ($path in $paths) {
    if (-not (Test-Path -LiteralPath $path)) { [ordered]@{path=$path; exists=$false}; continue }
    $item = Get-Item -LiteralPath $path -Force
    $acl = Get-Acl -LiteralPath $path
    $isReparse = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    $target = @(); if ($item.PSObject.Properties['Target']) { $target = @($item.Target) }
    $resolved = $null
    if ($isReparse) { $resolved = (& fsutil reparsepoint query $path 2>&1 | Out-String).Trim(); $code=$LASTEXITCODE } else { $code=$null }
    $entries = @($acl.Access | ForEach-Object {
        [ordered]@{identity=$_.IdentityReference.Value; type=$_.AccessControlType.ToString(); rights=$_.FileSystemRights.ToString(); inherited=$_.IsInherited; inheritance=$_.InheritanceFlags.ToString(); propagation=$_.PropagationFlags.ToString()}
    })
    [ordered]@{
        path=$path; exists=$true; directory=[bool]$item.PSIsContainer; owner=$acl.Owner;
        sddl=$acl.Sddl; protected=$acl.AreAccessRulesProtected;
        attributes=$item.Attributes.ToString(); attributes_numeric=[int]$item.Attributes;
        reparse=$isReparse; link_type=$item.LinkType; targets=$target; reparse_query=$resolved; reparse_query_exit=$code;
        standard_local_interactive_group_access=[AclProbe]::StandardGroupAccess($acl.GetSecurityDescriptorBinaryForm(), $groupSids);
        aces=$entries;
        sha256=$(if (-not $item.PSIsContainer) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } else { $null })
    }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$os = Get-CimInstance Win32_OperatingSystem
$tool = Join-Path $volume 'tools\zstd\zstd.exe'
$out = [ordered]@{
    schema='windows-lab-acl-probe/v1'; source_commit=(git rev-parse HEAD).Trim();
    os=[ordered]@{caption=$os.Caption; version=$os.Version; build=$os.BuildNumber};
    image_os=$env:ImageOS; image_version=$env:ImageVersion; system_directory=$buffer.ToString();
    process_user=$identity.Name; process_user_sid=$identity.User.Value;
    process_admin_member=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
    method='Read-only Get-Acl/Get-Item and Windows AuthzAccessCheck(MAXIMUM_ALLOWED) against DACL. Synthetic non-owner standard local interactive user plus listed enabled groups; no privileges, account creation, login, impersonation, write attempt, package install or ACL modification. Not proof of an actual separate unelevated logon; no owner-specific or other user-specific grants included; mandatory integrity policy not modeled.';
    group_sids=$groupSids;
    zstd_version=$(if (Test-Path -LiteralPath $tool) { (& $tool --version | Out-String).Trim() } else { $null });
    paths=@($results)
}
# Positive/negative controls exercise the same OS access-check implementation without filesystem writes.
$checks = @(
    @{sddl="O:BAG:BAD:(A;;FA;;;BU)"; expected=$true; name='Users full access'},
    @{sddl="O:BAG:BAD:(A;;FA;;;BA)(A;;FRFX;;;BU)"; expected=$false; name='Admins write, Users read'},
    @{sddl="O:BAG:BAD:(D;;0x2;;;BU)(A;;FA;;;AU)"; expected=$false; name='Users deny beats Authenticated Users grant'},
    @{sddl="O:BAG:BAD:(A;OIIO;FA;;;BU)(A;;FRFX;;;BU)"; expected=$false; name='Inherit-only write is not effective on current object'}
)
$controls = foreach ($check in $checks) {
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($check.sddl)
    $bytes = [byte[]]::new($descriptor.BinaryLength); $descriptor.GetBinaryForm($bytes, 0)
    $access = [AclProbe]::StandardGroupAccess($bytes, $groupSids)
    if ($access['write_data_or_add_file'] -ne $check.expected) { throw ('ACL probe control failed: '+$check.name) }
    [ordered]@{name=$check.name; expected_write=$check.expected; observed_write=$access['write_data_or_add_file']; access=$access}
}
$out.controls = @($controls)
Write-Output 'ACL_PROBE_JSON_BEGIN'
Write-Output ($out | ConvertTo-Json -Depth 12 -Compress)
Write-Output 'ACL_PROBE_JSON_END'
Write-Output 'ACL_PROBE_COMPLETE: read-only filesystem metadata and OS authorization checks; controls passed'
