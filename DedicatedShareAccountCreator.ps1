#Requires -RunAsAdministrator

$Username = "shareaccount"
$Password = ConvertTo-SecureString "changeme" -AsPlainText -Force # This should be from the keyboard (but I doubt SecureString's effectiveness anyway [though there's .NET password managers!])
$ShareNamesAndDirs = @{
    'share$' = "$env:USERPROFILE\Music"
}
$DirsToAddShareAccAceTo = @("$env:USERPROFILE\Music")
$AllowedIPs = "192.168.1.1/255.255.255.255,192.168.1.2/255.255.255.255"
$SshServerPort = 22

$MakeDedicatedAccount = $true
$HideAccountFromLogonUserList = $false
$ShareFolder = $true
$EnableFileSharingInFirewallForPrivateNetworks = $true
$DisableRemoteAssistance = $false
$EnableRemoteDesktop = $false
$InstallSshServer = $false

$overridesFile = Join-Path -Path $PSScriptRoot -ChildPath 'overrides.ps1' 
if (Test-Path $overridesFile -PathType Leaf) {
    Write-Host "Loading $overridesFile"
    . $overridesFile
}

## 1.
if ($MakeDedicatedAccount) {
    $Password.MakeReadOnly()

    if (-not (Get-LocalUser -Name $Username -ErrorAction 'SilentlyContinue')) {
        New-LocalUser -Name $Username -NoPassword
    }
    Set-LocalUser -Name $Username -Password $Password -AccountNeverExpires -PasswordNeverExpires $true -UserMayChangePassword $false

    $Password.Dispose()

    $adsi = [System.DirectoryServices.DirectoryEntry]"WinNT://./$Username,user"
    $adsi.InvokeSet("Profile", "C:\NUL")
    $adsi.InvokeSet("HomeDirectory", "C:\NUL")
    $adsi.CommitChanges()

    # Prevent account from being logged on for use outside of network purposes 
    Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "UserRightsLsa.psm1")
    Add-UserRight -Username $Username -Rights SeDenyInteractiveLogonRight,SeDenyRemoteInteractiveLogonRight,SeDenyServiceLogonRight,SeDenyBatchLogonRight
}

## 2.
if ($HideAccountFromLogonUserList) { # (optional: if an account isn't in the Users group, it won't be displayed anyway)
    $registryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    New-Item -Path $registryKeyPath -Force | Out-Null
    Set-ItemProperty -Path $registryKeyPath -Name $Username -Value 0 -Type "DWord"
}

## 3.
if ($ShareFolder) {
    foreach ($SharedDirectory in $DirsToAddShareAccAceTo) {
        # Add ACE to a folder to allow newly-added account to access the folder
        $acl = Get-Acl -Path $SharedDirectory
        $permission = $Username, "Modify,DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Allow"

        $aceExists = $acl.Access | Where-Object {
            $_.IdentityReference.Value -eq $permission[0] -and
            $_.FileSystemRights -eq $permission[1] -and
            $_.InheritanceFlags -eq $permission[2] -and
            $_.PropagationFlags -eq $permission[3] -and
            $_.AccessControlType -eq $permission[4]
        }

        if ($null -eq $aceExists) {
            $accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permission
            $acl.AddAccessRule($accessRule)
            Set-Acl -Path $SharedDirectory -AclObject $acl
        }
    }

    # Add share
    foreach ($share in $ShareNamesAndDirs.GetEnumerator()) {
        & "C:\Windows\System32\net.exe" share "$($share.Key)" /DELETE *> $null
        Start-Process -FilePath "C:\Windows\System32\net.exe" -ArgumentList "share `"$($share.Key)=$($share.Value.TrimEnd('\'))`" /Grant:$Username,READ /Grant:$Username,CHANGE /USERS:2 /CACHE:None" -NoNewWindow -Wait
        Set-SmbShare -Name $share.Key -FolderEnumerationMode AccessBased -Force -ErrorAction 'SilentlyContinue'
    }
}

## 4.
if ($EnableFileSharingInFirewallForPrivateNetworks) {
    Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Text;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public class MuiString {
    [DllImport("shlwapi.dll", SetLastError = false, ExactSpelling = true)]
    private static extern int SHLoadIndirectString([MarshalAs(UnmanagedType.LPWStr)] string pszSource, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszOutBuf, uint cchOutBuf, IntPtr ppvReserved);

    public static string GetIndirectString(string indirectString) {
        if (String.IsNullOrWhiteSpace(indirectString))
            return string.Empty;
        var lptStr = new StringBuilder(4096);
        return SHLoadIndirectString(indirectString, lptStr, (uint)lptStr.Capacity, IntPtr.Zero) == 0 ? lptStr.ToString() : string.Empty;
    }
}

namespace dtshLib
{
    [CoClass(typeof(DetectionAndSharingClass))]
    [Guid("1FDA955C-61FF-11DA-978C-0008744FAAB7")]
    [ComImport]
    public interface DetectionAndSharing : IDetectionAndSharing
    {
    }

    [TypeLibType(2)]
    [ClassInterface(ClassInterfaceType.None)]
    [Guid("1FDA955B-61FF-11DA-978C-0008744FAAB7")]
    [ComImport]
    public class DetectionAndSharingClass : IDetectionAndSharing, DetectionAndSharing
    {
        /*[MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        public extern DetectionAndSharingClass();*/
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        public virtual extern void GetStatus([ComAliasName("dtshLib.DtshType")] [In] DtshType DtshType, [ComAliasName("dtshLib.DtshState")] out DtshState pState, [ComAliasName("dtshLib.DtshAction")] [In] [Out] ref DtshAction pAvailableAction);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        public virtual extern void TurnOn([ComAliasName("dtshLib.wireHWND")] [In] ref _RemotableHandle hwndParent, [ComAliasName("dtshLib.DtshType")] [In] DtshType DtshType, [In] int bOn);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        public virtual extern NET_FW_PROFILE_TYPE2_ GetCurrentFwProfile();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        public virtual extern void GetStatusForProfile([In] NET_FW_PROFILE_TYPE2_ fwProfileType, [ComAliasName("dtshLib.DtshType")] [In] DtshType DtshType, [ComAliasName("dtshLib.DtshState")] out DtshState pState, [ComAliasName("dtshLib.DtshAction")] [In] [Out] ref DtshAction pAvailableAction);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        public virtual extern void TurnOnForProfile([ComAliasName("dtshLib.wireHWND")] [In] ref _RemotableHandle hwndParent, [In] NET_FW_PROFILE_TYPE2_ fwProfileType, [ComAliasName("dtshLib.DtshType")] [In] DtshType DtshType, [In] int bOn);
    }

    public enum DtshAction
    {
        Toggle,
        TurnOffAndEnableFw,
        TurnOnAndDisableFwBlockAllIncoming,
        NoneFwDisabled,
        NoneFwGpOverride,
        NoneThirdPartyFwInstalled
    }

    public enum DtshState
    {
        Off,
        On,
        Custom
    }

    public enum DtshType
    {
        Discovery,
        FileSharing,
        MediaSharing,
        DiscoveryAndFileSharing,
        All,
        DtshTypeMax
    }

    [Guid("1FDA955C-61FF-11DA-978C-0008744FAAB7")]
    [InterfaceType(1)]
    [TypeLibType(128)]
    [ComImport]
    public interface IDetectionAndSharing
    {
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void GetStatus([ComAliasName("dtshLib.DtshType")] [In] DtshType DtshType, [ComAliasName("dtshLib.DtshState")] out DtshState pState, [ComAliasName("dtshLib.DtshAction")] [In] [Out] ref DtshAction pAvailableAction);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void TurnOn([ComAliasName("dtshLib.wireHWND")] [In] ref _RemotableHandle hwndParent, [ComAliasName("dtshLib.DtshType")] [In] DtshType DtshType, [In] int bOn);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        NET_FW_PROFILE_TYPE2_ GetCurrentFwProfile();
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void GetStatusForProfile([In] NET_FW_PROFILE_TYPE2_ fwProfileType, [ComAliasName("dtshLib.DtshType")] [In] DtshType DtshType, [ComAliasName("dtshLib.DtshState")] out DtshState pState, [ComAliasName("dtshLib.DtshAction")] [In] [Out] ref DtshAction pAvailableAction);
        [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
        void TurnOnForProfile([ComAliasName("dtshLib.wireHWND")] [In] ref _RemotableHandle hwndParent, [In] NET_FW_PROFILE_TYPE2_ fwProfileType, [ComAliasName("dtshLib.DtshType")] [In] DtshType DtshType, [In] int bOn);
    }

    public enum NET_FW_PROFILE_TYPE2_
    {
        NET_FW_PROFILE2_DOMAIN = 1,
        NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE2_PUBLIC = 4,
        NET_FW_PROFILE2_ALL = 2147483647
    }

    public enum _DtshAction
    {
        Toggle,
        TurnOffAndEnableFw,
        TurnOnAndDisableFwBlockAllIncoming,
        NoneFwDisabled,
        NoneFwGpOverride,
        NoneThirdPartyFwInstalled
    }

    public enum _DtshState
    {
        Off,
        On,
        Custom
    }

    public enum _DtshType
    {
        Discovery,
        FileSharing,
        MediaSharing,
        DiscoveryAndFileSharing,
        All,
        DtshTypeMax
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct _RemotableHandle
    {
        public int fContext;
        public __MIDL_IWinTypes_0009 u;
    }

    [StructLayout(LayoutKind.Explicit, Pack = 4)]
    public struct __MIDL_IWinTypes_0009
    {
        [FieldOffset(0)]
        public int hInproc;
        [FieldOffset(0)]
        public int hRemote;
    }
}
"@

    # Manipulate File Sharing settings ala the Network and Sharing Centre
    $dtsh = New-Object -TypeName dtshLib.DetectionAndSharingClass
    #[dtshLib.DtshState]$state = [dtshLib.DtshAction]$availableAction = 0
    #$dtsh.GetStatusForProfile([dtshLib.NET_FW_PROFILE_TYPE2_]::NET_FW_PROFILE2_PRIVATE, [dtshLib.DtshType]::FileSharing, [ref]$state, [ref]$availableAction)

    # Restore original inbound IP settings changed by this script (a quick exit here serves as an undo)
    $fw = New-Object -ComObject HNetCfg.FwPolicy2
    $FileSharingInboundEnabledPrivate = $fw.rules | Where-Object {$_.Direction -eq 1 -and $_.Enabled -and $_.Profiles -eq 2 -and (([MuiString]::GetIndirectString($_.Grouping) -eq "File and Printer Sharing") -or $_.Grouping -eq "File and Printer Sharing")}
    ForEach ($FwRule in $FileSharingInboundEnabledPrivate) {
        $FwRule.RemoteAddresses = "LocalSubnet"
    }

    # Turn off file sharing for all profiles to get the firewall rules into a consistent state
    $dtsh.TurnOnForProfile([ref]$(New-Object -TypeName dtshLib._RemotableHandle), [dtshLib.NET_FW_PROFILE_TYPE2_]::NET_FW_PROFILE2_ALL, [dtshLib.DtshType]::FileSharing, $false)
    # Enable file sharing for private networks
    $dtsh.TurnOnForProfile([ref]$(New-Object -TypeName dtshLib._RemotableHandle), [dtshLib.NET_FW_PROFILE_TYPE2_]::NET_FW_PROFILE2_PRIVATE, [dtshLib.DtshType]::FileSharing, $true)
    # Disable network discovery
    $dtsh.TurnOnForProfile([ref]$(New-Object -TypeName dtshLib._RemotableHandle), [dtshLib.NET_FW_PROFILE_TYPE2_]::NET_FW_PROFILE2_ALL, [dtshLib.DtshType]::Discovery, $false)

    # Only allow specific IP addresses in
    $FileSharingInboundEnabledPrivate = $fw.rules | Where-Object {$_.Direction -eq 1 -and $_.Enabled -and $_.Profiles -eq 2 -and (([MuiString]::GetIndirectString($_.Grouping) -eq "File and Printer Sharing") -or $_.Grouping -eq "File and Printer Sharing")}
    ForEach ($NewRule in $FileSharingInboundEnabledPrivate) {
        $NewRule.RemoteAddresses = $AllowedIPs
    }
}

## 5.
if ($DisableRemoteAssistance) {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0 -Type 'DWord'
    Set-NetFirewallRule -Group "@FirewallAPI.dll,-33002" -Enabled False
}

## 6.
if ($EnableRemoteDesktop) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type 'DWord'
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "updateRDStatus" -Value 1 -Type 'DWord'
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type 'DWord'
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2 -Type 'DWord'

    Set-NetFirewallRule -Group "@FirewallAPI.dll,-28752" -Enabled False
    # defaults: All profiles, Any ip addresses
    Set-NetFirewallRule -Group "@FirewallAPI.dll,-28752" -Direction Inbound -Enabled True -Profile Private -RemoteAddress $($AllowedIPs -Split ",")
}

## 7.
if ($InstallSshServer) {
    Get-WindowsCapability -Online | Where-Object {($_.Name -like 'OpenSSH.Client*' -or $_.Name -like 'OpenSSH.Server*') -and $_.State -ne 'Installed'} | ForEach-Object {
        Add-WindowsCapability -Online -Name $_.Name
    }

    Stop-Service sshd -ErrorAction 'SilentlyContinue'
    Remove-NetFirewallRule -Name 'OpenSSH-Server-In-TCP-DedicatedShareAccountCreator' -ErrorAction 'SilentlyContinue'
    if ($SshServerPort -eq 22) {
        if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
            Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
            New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH SSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
        } else {
            Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
        }
        Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Enabled True
    } else {
        Start-Service sshd
        Stop-Service sshd
        
        $content = Get-Content -Path "C:\Windows\System32\OpenSSH\sshd_config_default"
        $content = $content -replace "#Port 22", "Port $SshServerPort"
        $content = $content -replace "#AddressFamily any", "AddressFamily inet"
        $content = $content -replace "#ListenAddress 0.0.0.0", "ListenAddress 0.0.0.0:$SshServerPort"
        Set-Content -Path "C:\ProgramData\ssh\sshd_config" -Value $content

        Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Enabled False -ErrorAction 'SilentlyContinue'
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP-DedicatedShareAccountCreator' -DisplayName 'OpenSSH SSH Server (sshd) - DedicatedShareAccountCreator' -Description 'Inbound rule for OpenSSH SSH Server (sshd)' -Enabled True -Direction Inbound -Program '%SystemRoot%\system32\OpenSSH\sshd.exe' -Protocol TCP -Action Allow -LocalPort $SshServerPort -Profile Private -RemoteAddress $($AllowedIPs -Split ",") | Out-Null
    }

    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
}