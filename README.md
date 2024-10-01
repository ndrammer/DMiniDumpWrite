# DMiniDumpWrite

Uses [DInvoke](https://github.com/TheWover/DInvoke)  from [TheWover](https://github.com/TheWover) to invoke dynamically MiniDumpWriteDump function and dump LSASS process memory.

It also uses DInvoke  for calling all the Native APIs needed. Dump is directly processed from memory to a compressed file to minimize detection using a callback function in MiniDumpWriteDump thanks to callback code in  [https://github.com/ricardojoserf/lsass-dumper-csharp](https://github.com/ricardojoserf/lsass-dumper-csharp) 

--------------------------

### Usage

It is necessary to have SeDebugPrivilege. You can use basic scripts from [pwshSeDebug](https://github.com/ndrammer/pwshSeDebug).

```
.\DMiniDumpWrite
```
Dump file is saved to dump.dmp.gz

Dump file can be processed with pypykatz:

```
pypykatz lsa minidump dump.dmp
```

It is also recommended to protect the assembly with [ConfuserEx](https://github.com/yck1509/ConfuserEx) tool to avoid signature detection.
