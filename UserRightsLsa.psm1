Add-Type @'
// Further derived from https://stackoverflow.com/a/14469248

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using LSA_HANDLE = System.IntPtr;

public class UserRightsLsa
{
    private const int POLICY_CREATE_ACCOUNT = 0x00000010;
    private const int POLICY_LOOKUP_NAMES = 0x00000800;

    private const int STATUS_SUCCESS = 0x00000000;
    private const int STATUS_ACCESS_DENIED = unchecked((int)0xC0000022);
    private const int STATUS_INSUFFICIENT_RESOURCES = unchecked((int)0xC000009A);
    private const int STATUS_NO_MEMORY = unchecked((int)0xC0000017);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint LsaNtStatusToWinError(int Status);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES
    {
        internal uint Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal uint Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int LsaOpenPolicy(
        LSA_UNICODE_STRING[] SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccessMask,
        out LSA_HANDLE PolicyHandle
    );

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int LsaAddAccountRights(
        LSA_HANDLE PolicyHandle,
        byte[] AccountSid,
        LSA_UNICODE_STRING[] UserRights,
        uint CountOfRights
    );

    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern int LsaClose(LSA_HANDLE ObjectHandle);

    private static Exception HandleLsaError(int ntStatus)
    {
        switch (ntStatus)
        {
            case STATUS_SUCCESS:
                return null;
            case STATUS_ACCESS_DENIED:
                return new UnauthorizedAccessException();
            case STATUS_INSUFFICIENT_RESOURCES:
            case STATUS_NO_MEMORY:
                return new OutOfMemoryException();
            default:
                return new Win32Exception((int)LsaNtStatusToWinError(ntStatus));
        }
    }

    private static LSA_UNICODE_STRING InitLsaString(string szString)
    {
        if (szString.Length > 0x7ffe)
            throw new ArgumentException("szString");

        return new LSA_UNICODE_STRING
        {
            Buffer = szString,
            Length = (ushort)(szString.Length * sizeof(char)),
            MaximumLength = (ushort)((szString.Length + 1) * sizeof(char))
        };
    }

    public static void Add(string username, string[] rights)
    {
        if (rights == null || rights.Length == 0)
            throw new ArgumentNullException("rights");

        SecurityIdentifier user;
        if (string.IsNullOrEmpty(username))
        {
            user = WindowsIdentity.GetCurrent().User;
        }
        else
        {
            try
            {
                user = new SecurityIdentifier(username);
            }
            catch
            {
                user = (SecurityIdentifier) new NTAccount(username).Translate(typeof(SecurityIdentifier));
            }
        }

        var sid = new byte[user.BinaryLength];
        user.GetBinaryForm(sid, 0);

        var userRights = new LSA_UNICODE_STRING[rights.Length];
        for (var i = 0; i < userRights.Length; ++i)
            userRights[i] = InitLsaString(rights[i]);

        var objectAttributes = new LSA_OBJECT_ATTRIBUTES();
        var lsaPolicyHandle = LSA_HANDLE.Zero;
        try
        {
            Exception ex;
            if ((ex = HandleLsaError(LsaOpenPolicy(null, ref objectAttributes,
                    POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, out lsaPolicyHandle))) != null)
                throw ex;

            if ((ex = HandleLsaError(LsaAddAccountRights(lsaPolicyHandle, sid, userRights, (uint)userRights.Length))) !=
                null)
                throw ex;
        }
        finally
        {
            if (lsaPolicyHandle != LSA_HANDLE.Zero)
                LsaClose(lsaPolicyHandle);
        }
    }
}
'@

function Add-UserRight {
	param(
        [string]$Username,
        [parameter(Mandatory)][string[]]$Rights
    )

    [UserRightsLsa]::Add($Username, $Rights)
}