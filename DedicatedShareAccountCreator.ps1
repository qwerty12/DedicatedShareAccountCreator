#Requires -RunAsAdministrator

$Username = "shareaccount"
$Password = ConvertTo-SecureString "changeme" -AsPlainText -Force # This should be from the keyboard (but I doubt SecureString's effectiveness anyway [though there's .NET password managers!])
$ShareName = "share$"
$SharedDirectory = "$env:USERPROFILE\Music"
$AllowedIPs = "192.168.1.1/255.255.255.255,192.168.1.2/255.255.255.255"

## 1. Make dedicated account
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
Import-Module -Name $(Join-Path -Path $PSScriptRoot -ChildPath "UserRights.psm1")
Grant-UserRight -Account $Username -Right SeDenyInteractiveLogonRight,SeDenyRemoteInteractiveLogonRight,SeDenyServiceLogonRight,SeDenyBatchLogonRight

## 2. Hide account from logon user list
if ($false) { # (optional: if an account isn't in the Users group, it won't be displayed anyway)
    $registryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    New-Item -Path $registryKeyPath -Force | Out-Null
    Set-ItemProperty -Path $registryKeyPath -Name $Username -Value 0 -Type "DWord"
}

## 3. Add ACE to a folder to allow newly-added account to access the folder
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

## 4. Add share
Remove-SmbShare -Name $ShareName -Force
Start-Process -FilePath "C:\Windows\System32\net.exe" -ArgumentList "share `"$ShareName=$SharedDirectory`" /Grant:$Username,READ /Grant:$Username,CHANGE /USERS:2 /CACHE:None" -NoNewWindow -Wait
Set-SmbShare -Name $ShareName -FolderEnumerationMode AccessBased -Force

## 5. Enable File Sharing in the firewall for private networks
Add-Type -Language CSharp @"
using System;
using System.Text;
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
"@

# Enable File Sharing ala the Network and Sharing Centre
Add-Type -TypeDefinition @"
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

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
