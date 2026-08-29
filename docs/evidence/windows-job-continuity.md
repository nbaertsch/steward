# Windows Job Object continuity evidence

## Status

**Narrowed, not closed.** Microsoft documentation and an executable local
spike establish why an independent retained handle is required for a restarted
service to reopen a named Job Object. SCM ordering, service upgrade, keeper
crash, reboot, atomic launch, nested-job, Docker, and supported Windows Host
behavior remain to be proven before E-05 closes.

The repeatable spike is in
[`spikes/windows-job-continuity`](../../spikes/windows-job-continuity).

## Documented semantics

- A Job Object is destroyed only after its last user handle is closed and all
  associated processes have exited.
- When the handle count reaches zero first, the object name is removed from the
  namespace even though process references keep the kernel object and its
  limits alive. User mode can no longer reopen that object by name.
- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` instead terminates associated processes
  when the last user handle closes.
- A named object can be reopened only while its name remains available.
- Windows 10 added `PROC_THREAD_ATTRIBUTE_JOB_LIST`, which assigns the process
  to the Job Object during process creation and closes the
  create-suspended/assign race.
- PID is not a durable process identity. Recovery must verify PID plus process
  creation time and Job Object membership.
- Reboot destroys all processes, handles, and Job Objects; recovery after
  reboot is TaskType checkpoint/restart/interruption, never Job Object reclaim.

## Observed results

Environment:

- Windows 10.0.26200, x64;
- .NET SDK 9.0.317;
- spike target `net9.0` for the first run; repository version targets
  `net8.0` without changing the Win32 calls.

### Only creator handle

1. A creator opened `Local\Steward.JobObjectSpike`.
2. It launched PowerShell sleeping for 300 seconds and assigned it to the Job
   Object.
3. It closed its Job Object handle and exited.
4. The child remained alive.
5. A second process called `OpenJobObject`.

Observed result: `OpenJobObject` failed with Win32 error 2
(`ERROR_FILE_NOT_FOUND`). The active child did not make the name reopenable.
Windows object-manager evidence shows that process references keep the
now-nameless Job Object and its limits alive, but a replacement Steward process
cannot reacquire its management handle by name.

### Independently retained handle

1. The creator opened the named Job Object and assigned a sleeping child.
2. A second process opened and retained a handle.
3. The creator closed its handle and exited.
4. A third process reopened the same name and called `IsProcessInJob`.
5. It terminated the Job Object.

Observed result:

```text
creatorExited=True
open=true; isInJob=True
terminated=true
```

The retained handle preserved reopenability and the original process
membership across creator exit.

## Contract consequence

- If Windows Tasks must continue through Node service restart or upgrade, some
  process outside that restart boundary must retain each Job Object handle.
  It may be a dedicated HandleKeeper or another proven long-lived Supervisor;
  the behavior matters more than the component name.
- Without a retained handle, Node restart cannot truthfully reclaim the Job
  Object by name. The attempt follows its declared interruption policy and
  cannot be relaunched until live-process evidence is reconciled.
- `KILL_ON_JOB_CLOSE` is incompatible with continuation across the last-handle
  boundary.
- Handle retention does not promise continuity across Host reboot or
  correlated keeper/Supervisor loss.
- Reclaim validates the expected Job name, Node incarnation, TaskAttempt
  generation, full process list, and PID creation times before adopting.
- `PROC_THREAD_ATTRIBUTE_JOB_LIST` is the preferred atomic assignment mechanism
  on supported Windows builds; persist-before-effect ordering around process
  creation still needs a crash-injection design.

## Remaining executable matrix

1. Run as actual Windows services under SCM.
2. Restart and upgrade Node while the keeper remains installed and running.
3. Kill the keeper before, during, and after Node restart.
4. Verify SCM dependency and MSI stop/start ordering.
5. Reboot and confirm cold-start interruption semantics.
6. Fuzz PID reuse and creation-time validation.
7. Crash around journal, process creation, Job assignment, and resume.
8. Exercise `PROC_THREAD_ATTRIBUTE_JOB_LIST`.
9. Exercise nested jobs, Docker Desktop, WSL2, build tools, and breakaway
   attempts on every supported Windows Host image.

## Sources

- [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [CreateJobObjectW](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-createjobobjectw)
- [OpenJobObject](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openjobobjecta)
- [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
- [Process handles and identifiers](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers)
- [Kernel object name lifetime](https://scorpiosoftware.net/2023/05/15/kernel-object-names-lifetime/)
- [Assigning a process to a Job Object at creation](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812)
