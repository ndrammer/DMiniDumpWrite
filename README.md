# DMiniDumpWrite

Uses [DInvoke](https://github.com/TheWover/DInvoke)  from [TheWover](https://github.com/TheWover) to invoke dynamically MiniDumpWriteDump function and dump LSASS process memory.

It also uses DInvoke  for calling all the Native APIs needed.

--------------------------

### Usage

It is necessary to have SeDebugPrivilege. You can use basic scripts from [pwshSeDebug](https://github.com/ndrammer/pwshSeDebug).

```
.\DMiniDumpWrite
```
Dump file is saved to C:\Windows\Temp\du_du.dux

Dump file can be processed with pypykatz:

```
pypykatz lsa minidump du_du.dux
```

It is also recommended to protect the assembly with [ConfuserEx](https://github.com/yck1509/ConfuserEx) tool to avoid signature detection.

------

### LSASS is flagged

This project was a try to  understand and implement DInvoke framework with the target of creating an unflagged LSASS dump using MiniDumpWriteDump, but it is flagged when filehandle is closed.

Anyway it gives you time to 7zipped the dump if 7z is installed.

```
 ."C:\Program Files\7-Zip\7z.exe" a "C:\Windows\Temp\du_du.dux.7z" "C:\Windows\Temp\du_du.dux"
```



