function Invoke-RunAsWithCert
{   
    <#
        .SYNOPSIS
            Creates a new logon session with the specified certificate.
        
        .DESCRIPTION
            This cmdlet creates a new logon session with the specified certificate via PKINIT.

            It is meant to be run on a non domain-joined VM. The cmdlet has two modes: one that sets
            registry keys and one that patches LSASS memory to bypass client-side checks related
            to the domain controller's certificate. These checks fail when running on a machine that
            is not joined to the domain.

            In registry mode (the default), administrator privileges are needed to set the relevant
            registry keys (and restore them at the end). If the keys are already set, administrator
            privileges are not required. Moreover, the CA certificate must be added to the list of
            trusted certification authorities. If this method fails (e.g. because of a check that is not
            bypassed with the registry keys), the patch method can be tried instead. It is less elegant
            but will bypass any client-side check related to the KDC certificate.

            In patch mode (-PatchLsass), the KerbCheckKdcCertificate function in LSASS will be patched.
            As KerbCheckKdcCertificate is not exported by kerberos.dll, symbols need to be retrieved.
            For the symbols to be automatically retrieved by this cmdlet, the environment variable 
            _NT_SYMBOL_PATH needs to be defined (e.g. SRV*c:\symbols*https://msdl.microsoft.com/download/symbols).
            If the symbols are not already on disk, an Internet connection is needed to download them.
            The Windows SDK is also needed to download the symbols. By default, the script will
            look in C:\Program Files (x86)\Windows Kits\10\Debuggers\x64 to find the DLLs it
            needs (dbghelp.dll and symsrv.dll).
            
        .PARAMETER Certificate
            The certificate to use for PKINIT authentication
        .PARAMETER Domain
            The Active Directory domain to authenticate to.
        .PARAMETER Password
            The certificate password.
            Default: ""
        .PARAMETER Command
            The command to execute in the new logon session.
            Default: "powershell.exe"
        .PARAMETER PatchLsass
            Patch LSASS memory instead of using the registry.
        .PARAMETER DbgHelpPath
            The path to dbghelp.dll installed with the Windows SDK.
            Default: "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll"
            
        .EXAMPLE  
            Invoke-RunAsWithCert user.pfx -Domain CORP.LOCAL
            
            Description
            -----------
            Create a new logon session with the specified certificate and run powershell.exe.

        .EXAMPLE
            Invoke-RunAsWithCert user.pfx -Domain CORP.LOCAL -Password password123
            
            Description
            -----------
            Create a new logon session with the specified password protected certificate and run powershell.exe.
            
         .EXAMPLE
            Invoke-RunAsWithCert user.pfx -Domain CORP.LOCAL -Command cmd.exe
            
            Description
            -----------
            Create a new logon session with the specified certificate and run cmd.exe.
            
         .EXAMPLE
            Invoke-RunAsWithCert user.pfx -Domain CORP.LOCAL -PatchLsass
            
            Description
            -----------
            Patch LSASS and create a new logon session with the specified certificate.
            
    #>
    
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $Certificate,
        
        [Parameter(Mandatory = $True)]
        [String]
        $Domain,

        [Parameter()]
        [String]
        $Password = "",

        [Parameter()]
        [String]
        $Command = "powershell.exe",

        [Parameter()]
        [Switch]
        $PatchLsass,

        [Parameter()]
        [String]
        $DbgHelpPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll"
    )

    $paramPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
    $standaloneKdcValidation = (Get-ItemProperty -Path $paramPath).StandaloneKdcValidation
    $useCachedCRLOnlyAndIgnoreRevocationUnknownErrors = (Get-ItemProperty -Path $paramPath).UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors

    try {
        if (!$PatchLsass.IsPresent) {
            if ($standaloneKdcValidation -ne 0) {
                Set-ItemProperty -Path $paramPath -Name "StandaloneKdcValidation" -Value 0 -ErrorAction Stop
            }
            if ($useCachedCRLOnlyAndIgnoreRevocationUnknownErrors -ne 1) {
                Set-ItemProperty -Path $paramPath -Name "UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors" -Value 1 -ErrorAction Stop
            }
        }

        Add-Type -TypeDefinition $Source -Language CSharp;    
        [RunAsWithCert]::RunAs($Certificate, $Domain, $Password, $Command, $PatchLsass.IsPresent, $DbgHelpPath);
    } catch {
        throw
    } finally {
        if (!$PatchLsass.IsPresent) {
            if ($standaloneKdcValidation -eq $null) {
                Remove-ItemProperty -Path $paramPath -Name "StandaloneKdcValidation"
            } elseif ($standaloneKdcValidation -ne 0) {
                Set-ItemProperty -Path $paramPath -Name "StandaloneKdcValidation" -Value $standaloneKdcValidation
            }

            if ($useCachedCRLOnlyAndIgnoreRevocationUnknownErrors -eq $null) {
                Remove-ItemProperty -Path $paramPath -Name "UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors"
            } elseif ($useCachedCRLOnlyAndIgnoreRevocationUnknownErrors -ne 1) {
                Set-ItemProperty -Path $paramPath -Name "UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors" -Value $useCachedCRLOnlyAndIgnoreRevocationUnknownErrors
            }
        }
    }
}

$Source = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class RunAsWithCert
{
    const int LOGON_NETCREDENTIALS_ONLY = 2;

    const int CREATE_NEW_CONSOLE = 0x00000010;

    public enum CRED_MARSHAL_TYPE
    {
        CertCredential = 1,
        UsernameTargetCredential
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CERT_CREDENTIAL_INFO
    {
        public uint cbSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] rgbHashOfCert;
    }

    [Flags]
    public enum PROCESS_ACCESS_RIGHTS : uint
    {
        PROCESS_VM_OPERATION = 0x00000008,
        PROCESS_VM_READ = 0x00000010,
        PROCESS_VM_WRITE = 0x00000020,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES
    {
        public uint nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYMBOL_INFO
    {
        public uint SizeOfStruct;
        public uint TypeIndex;
        public ulong Reserved1;
        public ulong Reserved2;
        public uint Index;
        public uint Size;
        public ulong ModBase;
        public uint Flags;
        public ulong Value;
        public ulong Address;
        public uint Register;
        public uint Scope;
        public uint Tag;
        public uint NameLen;
        public uint MaxNameLen;
        public IntPtr Name;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(
        IntPtr handle
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessWithLogonW(
        String lpUsername,
        String lpDomain,
        String lpPassword,
        uint dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CredFree(
        IntPtr buffer
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredMarshalCredential(
        CRED_MARSHAL_TYPE CredType,
        IntPtr Credential,
        out IntPtr MarshaledCredential
    );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredUnmarshalCredential(
        IntPtr MarshaledCredential,
        out CRED_MARSHAL_TYPE CredType,
        out IntPtr Credential
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FreeLibrary(
        IntPtr hLibModule
    );

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string procedureName
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr LoadLibrary(
        string dllToLoad
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        PROCESS_ACCESS_RIGHTS dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId
    );

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out int lpNumberOfBytesRead
    );

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out int lpNumberOfBytesWritten
    );

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate bool FnSymInitialize(
        IntPtr hProcess,
        string UserSearchPath,
        bool fInvadeProcess
    );

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate ulong FnSymLoadModuleEx(
        IntPtr hProcess,
        IntPtr hFile,
        string ImageName,
        string ModuleName,
        ulong BaseOfDll,
        int DllSize,
        IntPtr Data,
        int Flags
    );

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private delegate bool FnSymFromName(
        IntPtr hProcess,
        string Name,
        out SYMBOL_INFO Symbol
    );

    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
    private delegate bool FnSymCleanup(
        IntPtr hProcess
    );

    static IntPtr GetFunctionAddress(string library, string functionName, string dbghelp)
    {
        IntPtr pDll = LoadLibrary(dbghelp);
        if (pDll == IntPtr.Zero)
        {
            throw new Exception(string.Format("LoadLibrary failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }

        IntPtr address = GetProcAddress(pDll, "SymInitializeW");
        if (address == IntPtr.Zero)
        {
            throw new Exception(string.Format("GetProcAddress failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }

        FnSymInitialize SymInitialize = (FnSymInitialize)Marshal.GetDelegateForFunctionPointer(address, typeof(FnSymInitialize));

        address = GetProcAddress(pDll, "SymLoadModuleExW");
        if (address == IntPtr.Zero)
        {
            throw new Exception(string.Format("GetProcAddress failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }

        FnSymLoadModuleEx SymLoadModuleEx = (FnSymLoadModuleEx)Marshal.GetDelegateForFunctionPointer(address, typeof(FnSymLoadModuleEx));

        address = GetProcAddress(pDll, "SymFromNameW");
        if (address == IntPtr.Zero)
        {
            throw new Exception(string.Format("GetProcAddress failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }

        FnSymFromName SymFromName = (FnSymFromName)Marshal.GetDelegateForFunctionPointer(address, typeof(FnSymFromName));

        address = GetProcAddress(pDll, "SymCleanup");
        if (address == IntPtr.Zero)
        {
            throw new Exception(string.Format("GetProcAddress failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }

        FnSymCleanup SymCleanup = (FnSymCleanup)Marshal.GetDelegateForFunctionPointer(address, typeof(FnSymCleanup));

        IntPtr hProcess = Process.GetCurrentProcess().SafeHandle.DangerousGetHandle();
        bool status = SymInitialize(hProcess, null, false);
        if (!status)
        {
            throw new Exception(string.Format("SymInitialize failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }

        Console.WriteLine(String.Format("Retrieving symbols for {0}...", library));

        UInt64 imageBase = SymLoadModuleEx(hProcess, IntPtr.Zero, library, null, 0, 0, IntPtr.Zero, 0);
        if (imageBase == 0)
        {
            throw new Exception(string.Format("SymLoadModuleEx failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }
        Console.WriteLine(string.Format("ImageBase: 0x{0:X}", imageBase));

        IntPtr baseAddress = LoadLibrary(library);
        if (baseAddress == IntPtr.Zero)
        {
            throw new Exception(string.Format("LoadLibrary failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }
        Console.WriteLine(string.Format("Base address: 0x{0:X}", (UInt64)baseAddress));

        SYMBOL_INFO symbolInfo = new SYMBOL_INFO();
        symbolInfo.SizeOfStruct = (uint)Marshal.SizeOf(typeof(SYMBOL_INFO));

        status = SymFromName(hProcess, functionName, out symbolInfo);
        if (!status)
        {
            throw new Exception(string.Format("SymFromName failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }
        Console.WriteLine(String.Format("{0} offset: 0x{1:X}", functionName, symbolInfo.Address));

        ulong functionAddress = (ulong)baseAddress + symbolInfo.Address - imageBase;
        Console.WriteLine(string.Format("{0} address: 0x{1:X}", functionName, functionAddress));

        SymCleanup(hProcess);
        FreeLibrary(pDll);
        FreeLibrary(baseAddress);

        return (IntPtr)functionAddress;
    }

    static string NameFromCert(X509Certificate2 cert)
    {
        string name = cert.GetNameInfo(X509NameType.UpnName, false);
        if (String.IsNullOrEmpty(name))
        {
            name = cert.GetNameInfo(X509NameType.DnsName, false).Split('.')[0] + "$";
        }
        else
        {
            name = name.Split('@')[0];
        }

        return name;
    }

    public static void RunAs(string certificate, string domain, string password, string command, bool patchLsass, string dbghelp)
    {
        IntPtr address = IntPtr.Zero;
        IntPtr hProcess = IntPtr.Zero;
        byte[] backup = new byte[3];

        if (patchLsass) {
            address = GetFunctionAddress(@"C:\Windows\System32\kerberos.dll", "KerbCheckKdcCertificate", dbghelp);

            Process[] processes = Process.GetProcessesByName("lsass");
            if (processes.Length == 0)
            {
                throw new Exception("Process lsass.exe not found");
            }

            hProcess = OpenProcess(
                PROCESS_ACCESS_RIGHTS.PROCESS_VM_OPERATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ | PROCESS_ACCESS_RIGHTS.PROCESS_VM_WRITE,
                false,
                (uint)processes[0].Id
            );
            if (hProcess == IntPtr.Zero)
            {
                throw new Exception(string.Format("OpenProcess failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
            }

            int read;
            bool status = ReadProcessMemory(
                hProcess,
                address,
                backup,
                3,
                out read
            );
            if (!status)
            {
                CloseHandle(hProcess);
                throw new Exception(string.Format("ReadProcessMemory failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
            }

            byte[] patch = new byte[3] { 0x33, 0xC0, 0xC3 }; // XOR EAX,EAX; RET;
            int written;
            status = WriteProcessMemory(
                hProcess,
                address,
                patch,
                3,
                out written
            );
            if (!status)
            {
                CloseHandle(hProcess);
                throw new Exception(string.Format("WriteProcessMemory failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
            }

            Console.WriteLine("Patched lsass memory");
        }

        try
        {
            X509Certificate2 cert = new X509Certificate2(certificate, password, X509KeyStorageFlags.PersistKeySet);
            using (X509Store store = new X509Store(StoreName.My))
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
            }
            string username = MarshalCertificate(cert);

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(si);
            si.lpTitle = string.Format("{0} (running as {1}\\{2})", command, domain, NameFromCert(cert));

            bool status = CreateProcessWithLogonW(
                username,
                domain,
                null,
                LOGON_NETCREDENTIALS_ONLY,
                null,
                command,
                CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                null,
                ref si,
                out pi
            );

            if (!status)
            {
                throw new Exception(string.Format("CreateProcessWithLogonW failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        catch
        {
            throw;
        }
        finally
        {
            if (patchLsass) {
                int written;
                bool status = WriteProcessMemory(
                    hProcess,
                    address,
                    backup,
                    3,
                    out written
                );
                CloseHandle(hProcess);

                if (!status)
                {
                    throw new Exception(string.Format("WriteProcessMemory failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
                }
                Console.WriteLine("Restored lsass memory");
            }
        }
    }

    // Taken from https://github.com/bongiovimatthew-microsoft/pscredentialWithCert/blob/master/SmartcardLogon/Program.cs
    static string MarshalCertificate(X509Certificate2 cert)
    {
        CERT_CREDENTIAL_INFO certInfo = new CERT_CREDENTIAL_INFO();
        certInfo.cbSize = (uint)Marshal.SizeOf(typeof(CERT_CREDENTIAL_INFO));
        certInfo.rgbHashOfCert = cert.GetCertHash();

        IntPtr pCertInfo = Marshal.AllocHGlobal(Marshal.SizeOf(certInfo));
        Marshal.StructureToPtr(certInfo, pCertInfo, false);

        IntPtr marshaledCredential = IntPtr.Zero;
        bool result = CredMarshalCredential(CRED_MARSHAL_TYPE.CertCredential, pCertInfo, out marshaledCredential);
        if (!result)
        {
            throw new Exception(string.Format("CredMarshalCredential failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }

        string username = Marshal.PtrToStringUni(marshaledCredential);

        Marshal.FreeHGlobal(pCertInfo);
        CredFree(marshaledCredential);

        return username;
    }
}
"@
