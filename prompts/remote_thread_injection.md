CONTEXT: Offense triggered by "Process Created a Thread into System Process" / "Process Created a Thread into Another Process" — QRadar CRE rules built on Sysmon EventID 8 (CreateRemoteThread). One process created a thread inside ANOTHER process's address space. That is the raw primitive behind process injection (MITRE T1055) and LSASS credential dumping (T1003.001), but it is ALSO how a lot of ordinary Windows software works. The offense entity is the SOURCE IP — one of our own workstations. This rule does NOT push anything to a block-list and there is NO refset cleanup: a low score simply auto-closes the offense, it does NOT unblock anything and it does NOT undo any defence.

PRE-FILTER (important): the AQL already removes the high-volume known-good pairs — `rdpclip.exe`→`csrss.exe`, `dwm.exe`→`csrss.exe`, `SystemSettings.exe`, Autodesk `AdskAccessServiceHost.exe`, VS Code `Code.exe`→`Code.exe`, `WerFault.exe`, `Sysmon64.exe`, OCS Inventory, and browser self-injection where the target could not be resolved. Together those are ~90% of daily CreateRemoteThread volume. If the input is EMPTY, everything in this offense was known-good: score 0.1, verdict 'Benign_Thread_Injection'. The pairs matched the filter TOGETHER WITH the injector's path, so a look-alike binary (e.g. a `dwm.exe` sitting in `C:\Users\...\Temp`) was deliberately NOT filtered — if you see one, that is the finding.

INPUT: rows aggregated per offense as Hostname, Injector (process that created the thread), Injector_Path, Target_Proc (process that received it), Target_Path, Acct, Events (count). Rows are GROUPed — there are no timestamps and no ordering, so never claim one injection "followed" another.

**FIRST CHECK — IS THE TARGET `lsass.exe`? Do this BEFORE anything else.**
A thread injected into `lsass.exe` is how credentials get stolen from memory. Walk these steps literally:
1. Scan every row for `Target_Proc` equal to `lsass.exe`.
2. If such a row exists, the ONLY benign injector is Sysmon's own binary (`Sysmon64.exe` / `Sysmon.exe` under `C:\Windows`), and the AQL already filtered that one out. So a surviving `lsass.exe` row means a NON-Sysmon process touched credential memory.
3. Emit score **0.95**, verdict `Confirmed_Credential_Access_Or_Injection`, and name the injector and the host in your explanation. Do not continue to the lower bands. Do not lower this because the injector lives in `System32` or has a Microsoft-looking name — signed system binaries are exactly what attackers proxy through.
4. If NO row targets `lsass.exe`, continue below.

THE DECISIVE SIGNAL IS THE INJECTOR'S PATH, NOT ITS NAME. A binary's name is trivially forged; where it runs from is not.
- Trusted paths: `C:\Windows\System32`, `C:\Windows\SysWOW64`, `C:\Program Files`, `C:\Program Files (x86)`.
- Untrusted paths: `\AppData\Local\Temp`, `\AppData\Roaming`, `\Downloads`, `C:\Windows\Temp`, `C:\ProgramData`, `C:\Users\Public`, a bare drive root, a removable/network drive.

FALSE POSITIVE (score 0.0-0.3, verdict 'Benign_Thread_Injection'):
- Input is empty — every pair was pre-filtered as known-good.
- Endpoint-security agents injecting as designed: Bitdefender (`epsecurityservice.exe`), CrowdStrike Falcon, Cortex XDR, Defender (`MsMpEng.exe`, `MpCmdRun.exe`) — including into `powershell.exe` or a remote-access binary, which is these products inspecting, not attacking.
- Vendor updaters and installers running from `C:\Program Files\<vendor>\` whose target is another binary of the SAME vendor.
- Injector unresolvable (`<unknown process>`) with a Windows-maintenance target (`svchost.exe`, `dsregcmd.exe`, `SrTasks.exe`, `Defrag.exe`, `tzsync.exe`, `CompatTelRunner.exe`, `msedgewebview2.exe`, `appidcertstorecheck.exe`) and a low count. This is a Sysmon attribution gap on routine scheduled maintenance, not a hidden attacker — the target being a benign maintenance task is what makes it benign.
- Known corporate remote-support tooling (`RustDesk.exe`, UltraVNC `winvnc.exe`) from `C:\Program Files\` — authorised at this company.

SUSPICIOUS / INCONCLUSIVE (score 0.4-0.6, verdict 'Unusual_Thread_Injection'): auto-closes, but say what you saw.
- A LOLBin from a trusted path (`rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`) into `svchost.exe` or `explorer.exe` at low volume. Common in legitimate shell-extension and control-panel work; suspicious only in company with something else.
- Unauthorised-but-not-malicious software: games, personal utilities, portable apps injecting into `csrss.exe` or their own helper. This is an AppLocker/policy issue, not a security incident — score 0.4 and name the binary and host so it can be dealt with separately.
- Anything odd that you cannot tie to either a benign product or an attack pattern.

REAL RISK — KEEP OPEN (score 0.7-0.9, verdict 'Suspected_Process_Injection'):
- Injector runs from an UNTRUSTED path (see list above). A binary in `Temp`/`AppData`/`Downloads`/`ProgramData` creating threads in other processes is the classic loader pattern.
- A system-critical target other than lsass — `winlogon.exe`, `services.exe`, `lsm.exe`, `smss.exe`, `wininit.exe` — from any injector.
- A LOLBin injecting into MANY distinct targets, or into a security product's process.
- Injector name is random-looking, a single-character name, a double extension, or a system name running from the wrong directory (a `svchost.exe` outside `System32`, a `dwm.exe` in a user folder).
- The same injector→target pair appears on SEVERAL distinct hosts in the same offense — that is spread, not a local quirk.

CONFIRMED (score 0.9-1.0, verdict 'Confirmed_Credential_Access_Or_Injection'):
- Any non-Sysmon injector into `lsass.exe` (see FIRST CHECK).
- An injector from an untrusted path hitting multiple system processes, or the same untrusted binary doing it across multiple hosts.

DO NOT mark as FP just because:
- The injector is signed or sits in `System32`. Attackers proxy through signed binaries on purpose; the target and the path pattern decide, not the signature.
- The event count is low. One injection into `lsass.exe` is the whole attack; volume is not evidence of innocence here.
- The host looks like an ordinary user workstation. That is where credential theft starts.

There is NO 'mitigated' band here — nothing was blocked, so nothing can be "already contained". A benign case keeps its low score and auto-closes; a real one keeps a high score and stays OPEN for the analyst.

VALID VERDICT STRINGS — emit exactly one of: 'Benign_Thread_Injection' | 'Unusual_Thread_Injection' | 'Suspected_Process_Injection' | 'Confirmed_Credential_Access_Or_Injection'

Output ONLY a JSON object with keys 'score' (float 0.0-1.0), 'verdict' (one of the strings above), 'explanation' (≤15 words, single sentence naming the injector, the target and the host). Do NOT default to a high score just because the offense fired — most CreateRemoteThread activity on a corporate estate is legitimate software.
