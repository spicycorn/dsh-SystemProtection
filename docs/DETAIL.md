# System file protection

Keeps the model from destroying the machine it is working on.

A model deletes a system file in two ways: it names the file directly, or it runs a shell command that reaches it. This plugin judges both, and its verdict is a **hard denial** for the tiers that must never be touched.

## How it enforces

| Layer | What it does | Why it matters |
| --- | --- | --- |
| Tool guard | `ctx.tools.guard()` returns a denial before the call executes | Monotonic and order-independent: a later listener cannot re-allow it, and the denial survives a `danger-full-access` retry, when the OS sandbox has already been switched off |
| Approval route | `tools/pre-execute` returns `ask` | Anything irreversible-looking but legitimate reaches you as a confirmation instead of a silent yes or no |
| File-system seam | `fs/delete-intent`, `fs/write-intent`, `fs/edit-intent`, registered first (`prepend: true`) | Catches a tool that bypasses the usual path; a Host-internal write with no attributed actor is left alone. When the plugin allows an operation it still calls `next()`, so any other listener on the same waterfall — an observation policy, say — keeps running underneath it |

Judgement is per path, in tiers, and the strictest hit wins. `system`, `harness`, `credentials`, `versionControl`, `trash`, the home directory and the workspace directory itself are **deny** by default; user folders, application data, secret files and `git` working-tree discards are **ask**; lockfiles are left alone. Configure any tier to `deny` / `ask` / `off`.

The plugin reads the *meaning* of a command, not just its first word: nested `bash -c` / `cmd /c` / `powershell -EncodedCommand` payloads (base64 decoded as UTF-16LE then UTF-8), `python -c "shutil.rmtree(...)"`, `find -delete`, `xargs`, `sudo`/`env`/`nice` prefixes, `cd /etc && rm passwd`, `--` terminators, redirections onto files and block devices, `git filter-branch` versus `git clean`, globs, `%USERPROFILE%` / `$env:SystemRoot` / `${HOME}` expansion, Windows extended-length and device prefixes, case-insensitive comparison on Windows only, and symlinks that point outside the workspace. It also reads the boot chain by command (`bcdedit`, `bootrec`, `bcdboot`, `bootsect`, `mbr2gpt`, `reagentc`, `mountvol`), `fsutil setzerodata`, `robocopy /MIR`, `forfiles`, the source of a code tool, and the text of a script the command would run.

Unknown tools (MCP servers, other bundles) are swept for path-shaped arguments whenever their name says they write, delete, move or patch — so a third-party `filesystem_remove` cannot delete `C:\Windows` while `read` of the same file stays possible.

## Who gets warned, and how

Two audiences need different sentences, and what the plugin may do for each is different.

**The person** gets an approval card for `userData`, `appData`, and `secrets`. `ApprovalRequest` carries `agent`, `toolName`, `callId`, `reason`, `displayReason` — no title, no severity, no source field — so a plugin cannot ask the Host to render its question in another colour or with another label. The text is the entire lever. The card therefore opens with a fixed marker, names the tier and the exact path, and tells the reader to demand a one-sentence reason and to reject when it does not come. `reason` stays the factual audit line; `displayReason` is what gets read. Outcomes are `allowed-once`: the plugin caches no answers, because a remembered yes for `~/.ssh` outlives the task that justified it.

**The model** gets one static section registered through `ctx.systemPrompt.section()` at order 3120 — after the tool sections, well before the persona suffix: the limits, an explicit ban on routing around a block, and the requirement to write the reason *before* the call. The text is static because the assembled prompt is committed as a surface node and replaced only when the text changes. `modelGuidance: false` drops the section, and a profile that provides no `systemPrompt` service logs a warning and enforces anyway.

## How 1.0.0 got its fixes

Every one of these was measured on a second machine, not imagined, and each one is a test now.

- **The install directory was unprotected.** Its location came only from `DSH_INSTALL_DIR` / `DSH_NODE_EXECUTABLE`, which a launcher exports for the *tool subprocesses* it spawns; the process running the plugin had neither. A packaged app is now read from inside itself — `process.versions.electron` with `execPath` and `resourcesPath`. The inference is refused for a plain `node` (which would make every write under `C:\Program Files\nodejs` a denial) and for a drive root, and it climbs `.app/Contents/{MacOS,Resources}` to the bundle.
- **`Get-Date | Format-Table` was denied as erasing a volume**, because the blanket table was matched by hyphen prefix. Blanket entries are matched exactly now; `Format-Volume` and `mkfs.ext4` still land.
- **A path one assignment away passed** — `$p = 'C:\…\.git\config'; Remove-Item -LiteralPath $p`. Literals the command assigns to its own variables are resolved, and the verdict notes record which variable was resolved to what, so a denial can be checked rather than trusted.

Attacking the fixed build then found two more that the report had not mentioned: `rm -rf /*` was judged as the glob rather than as the root, and `-LiteralPath C:\` lost its operand entirely because the tokenizer applied POSIX backslash escaping to PowerShell, where `\` is an ordinary character. Both are pinned as well, along with the negative controls that keep `rm -rf ./out/*` a normal cleanup.

## How 1.1.0 got its fixes

The first evaluation (1.0.0, 2026-11-25) attacked the installed 1.0.0 on a UEFI machine from a `danger-full-access` session. It found the path rules were good and the *non-path* ways to destroy a machine were not covered at all. Every finding is now a test.

- **Boot configuration was not in the scanner at all.** `bcdedit /delete {current} /f`, `bootrec /fixmbr`, `bcdboot`, `bootsect`, `mbr2gpt`, `reagentc /disable`, `mountvol S: /S` and `fsutil file setzerodata … ntoskrnl.exe` were allowed, because none of them names a path to delete. They are now denied by their own name and form; the read-only forms (`bcdedit /enum`, `reagentc /info`, bare `mountvol`) still pass, and `allowCommands` is the explicit way to permit one.
- **An EFI system partition has no drive letter.** `\\?\Volume{…}\EFI\Microsoft\Boot\BCD` and `S:\EFI\…` (after `mountvol S: /S`) matched no drive-letter rule. Boot structures — `\EFI`, `\boot`, `\Recovery`, `\$WinREAgent`, `\System Volume Information`, an offline `\Windows\System32` — are now judged on **every** volume, and a volume-GUID root is a volume root.
- **One file, several spellings.** This machine's administrative shares (`\\localhost\C$\Windows`, `\\<name>\ADMIN$\System32`), 8.3 short names (`C:\PROGRA~1`), `subst` drive letters and junctions are resolved and added to the judgement; the strictest spelling wins. Node's plain `realpathSync` does not expand 8.3 names, so the alias resolver uses the native one. A share on another machine is left as a network path.
- **`cmd /c "cd /d … && del relative"` moved the running directory to `C:\d`.** The `cd` reader now skips cmd's `/`-switches, so the relative delete resolves under the directory that was actually entered. The same fix taught the tokenizer not to treat a backslash as an escape in cmd/PowerShell, where it is an ordinary path character.
- **A script was data.** `pwsh -File .\cleanup.ps1` was allowed whatever the script contained. A script the command would *run* is now read — bounded to 256 KiB, eight files, no directory listing — and scanned before it runs. This is the one file-content read the plugin performs, `scanScripts: false` turns it off, and `test/no-touch.mjs` pins that it is the only read.
- **`robocopy /MIR`, `forfiles /c "cmd /c del @path"`, `sdelete`, copy destinations** are recognised: a mirror is a delete of everything the source does not have.
- **A code tool was not a shell.** `run_code` / `execute_code` / REPL-style tools are now read as code: file-API calls and literal `exec("…")` strings are judged, while ordinary source text is not fed to the shell tokenizer (so `format(x)` is never a volume format).
- **The plugin could be switched off from inside the session.** The `plugin_manager` / `plugin_market` exemption is kept, minus one call: a call that names this plugin and disables or removes it is denied (`PROTECTED_SELF`). `selfProtect: false` is the owner's way out.
- **Internal errors used to fail open.** `onInternalError` now defaults to `closed` on the guard and on the file-system seam: if the protection cannot decide, the call is refused rather than allowed.


## What the plugin never does

- It never deletes, moves, or rewrites anything itself. The only file it may write is an audit log you configure.
- It never reads a file except the bounded text of a script the tool call itself names to run (`pwsh -File x.ps1`, `bash ./build.sh`, `python x.py`): at most 256 KiB per file, at most eight files, never a directory listing, and off with `scanScripts: false`. The only other file-system calls it makes are `existsSync` / `lstatSync` / `statSync` / `realpathSync` on paths a call already named, to resolve symlinks, drives and 8.3 names.
- It never starts a process and never opens a socket.
- Its reach is the DSH process only. It hooks DSH's tool pipeline and DSH's file-system seam; programs that are not DSH are outside its world in both directions — it cannot restrict them, and it cannot be affected by them.
- The verdicts it produces are data, not actions: a guard denial is a returned object, a file-system denial is a thrown error. Nothing is carried out.
- It never contacts the network and collects no telemetry.
- It never blocks the Plugin Manager's ordinary management of bundles, but it does refuse the one call that would switch *this* plugin off from inside a session (`selfProtect: false` removes that check too).
- It never touches Harness-internal file operations that are not attributed to a tool call.

`test/no-touch.mjs` asserts exactly these claims at run time by replacing `node:fs`, `node:fs/promises`, `node:child_process`, `node:net` and `node:http` with recording proxies that throw on writes, then driving the plugin through hostile calls on all three layers.

## If you are blocked and should not be

The denial message names the tier and the exact path. Then, in rough order of preference:

1. Work inside the session workspace, or ask for the operation to be done by a human.
2. Add the one path to `allowExtra` (it beats every tier, including `system`).
3. Lower the tier: `tiers: { appData: "off" }`.
4. Widen the escape hatch for one tool: `sweepSkipTools`, `exemptTools`; for a command that names no path (`mountvol`, `bcdboot`), `allowCommands`.
5. Set `enforcement: "audit"` to watch what it *would* block before trusting it.

`/system-protection status` shows the live tier table and counters; `/system-protection test <command or path>` dry-runs a single call.

One consequence worth knowing: because `~/.dsh` and the active profile are in the `harness` tier, a tool call that tries to edit Harness's own state or patch file is denied — deliberately, since that is where the harness keeps its own configuration. If you want that for one specific file, name it in `allowExtra`.

The reverse case, which was found in a real session and is now handled: the plugin guards its own source so a model cannot delete the protection to switch itself off. When the plugin's directory sits *inside* the session workspace — the normal shape of a `link:` install someone is developing — that rule would deny every ordinary edit in the tree, so it yields to the workspace and the startup log warns that self-protection is off. Protection of the system, credential, Harness and version-control roots does not change, and a normally installed copy (under the profile) stays guarded by `harness:profile`.

The *other* direction matters just as much, and 1.2.0 fixes it: a Harness root can **contain** the workspace — the shipped portable layout puts `workspace` next to the executable. There the harness rule yields only for a target that is genuinely inside the workspace, so the workspace is usable while the executable, `resources`, the profile and the rest of the install tree stay denied, the workspace root itself stays denied as `workspaceRoot`, and a junction inside the workspace is resolved so it cannot smuggle a target into the install tree. A context that merely *simulates* another platform no longer borrows the host's `execPath` either: that produced a nonsense install root (`path.posix` turned a Windows path into `.`, and the folded key into `/`, protecting everything on the simulated Linux box).

## How 1.2.0 got its fixes

The second evaluation ([`系统保护插件测评报告-2026-11-25.md`](系统保护插件测评报告-2026-11-25.md)) was run on a Desktop host with the portable layout. Its verdict was blunt: the hard block works, but the plugin had one severe false positive and several trivial bypasses.

- **The workspace was unusable.** `D:\DeepSeek Harness\workspace` was classified `harness:install`, so every `write`, `edit` and workspace delete was denied — the plugin prevented the session from producing any file at all. The yield rule only handled the opposite direction. Fixed as described above, with the executable, `resources`, the workspace root and a junction escape pinned as tests.
- **The bundled suites failed on a Desktop runtime**, because the simulated Linux context inherited the host's `execPath`. Fixed by using the host executable only for the host platform (or an explicitly injected runtime), and by rejecting relative `appRootOf` results.
- **False positives from PowerShell syntax.** `$_.FullName`, `@('a','b')`, `$(…)`, `(Get-Item x).FullName` and `{ … }` were read as relative paths (and, inside the install tree, denied). They are now recognised as expressions; a variable that cannot be resolved from the command text is skipped rather than invented as a file. A script's comments are stripped before scanning, so `# rm -rf C:\Windows` in a header is not a denial, and `-WhatIf` previews are allowed because the engine promises nothing is changed.
- **`[System.IO.File]::Delete`, `[IO.Directory]::Delete`, `WriteAllText`, `Clear-Content`** were not seen at all; they are now judged, but only as call sites outside quotes.
- **`Start-Process … -ArgumentList '/c del …'`** hid the command from the scanner; it is now scanned as the command line it launches.
- **Base64 + `Invoke-Expression`** was only decoded for `-EncodedCommand`; a blob the command decodes itself is now decoded and scanned — decoding data without evaluating it stays allowed.
- **The code scanner missed `r"…"`, `require('fs').rmSync(…)`, `os.remove(…)`, `Path('…').unlink()`.** All are matched now, and a `.py` script using a raw string is judged like the inline form.
- **`fsutil file createnew`** is judged by its path instead of being denied wholesale: denied in a system tree, allowed in the workspace.
- **`git -C <repo> checkout .`** (and `reset --hard`, `filter-branch`) are recognised, and the finding names the repository the command selected.
- **`Get-ChildItem C:\Windows -Recurse | Remove-Item`** — a delete with no operand — now removes what the previous segment enumerated, so a pipeline wipe of a system tree is a denial; the same pipeline over a workspace folder stays allowed.

## How 1.3.0 got its fixes

The third round of probing found two ways around the path rules, one scheduling gap, and one false positive.

- **The raw volume namespace.** `\\?\GLOBALROOT\Device\HarddiskVolume1\Windows\…`, `\Device\HarddiskVolume2\…` and `\\.\HarddiskVolume1\…` name the same bytes as a drive letter, so they are now classified as a raw device: everything below them is `system`, for delete and for write, including the shadow-copy spelling.
- **`.com` executables.** `C:\Windows\System32\format.com` is the real format program; normalisation only stripped `.exe`, so `format.com C:` was allowed. `.com` is stripped now, and `Start-Process` without `-ArgumentList` scans the program together with its arguments instead of only the argument list.
- **`schtasks /tr`.** A scheduled task is executed later by the OS, outside any tool call, so its action is parsed at creation time: `schtasks /create … /tr "cmd /c del C:\Windows\…"` is denied; a benign action (`robocopy … /MIR` to a data folder) stays allowed, and a script named as the action is read and scanned like any other script.
- **The false positive.** The "mutation verb behind a wrapper" search is what lets `sudo -u bob rm -rf /usr` be read correctly, but it ran for *every* command whose first word was not a delete verb, so `Write-Output bcdedit /set …` was denied as if bcdedit had run. It now only runs while the line is still inside a wrapper (or one of its switches). The same principle is applied to code payloads: comments are stripped, and a `fs.rmSync('…')` that appears inside a string literal — a test fixture, a generator, this plugin's own tests — is data, not a call.



## Known limits

Shell inspection is analysis of text, and text can be evasive: a path assembled from variables set earlier, a script reached through `& $path` or `Invoke-Expression (Get-Content …)`, a payload downloaded at runtime, or a program that resolves its target internally can hide from the scanner. A script the command *names to run* is read and scanned (1.1.0), which closes the two-step "write a .ps1, then run it" route, but it is still reading text. A scheduled task's action is parsed at creation time when it is created with `schtasks /tr`; creating one through `Register-ScheduledTask` or a scheduler API inside a program is outside text analysis. Computed targets are skipped on purpose — `ForEach-Object { Remove-Item $_.FullName }` is not denied, because the target is not in the text and inventing one is exactly the false-positive class 1.2.0 removed — while a direct pipeline (`Get-ChildItem C:\Windows -Recurse | Remove-Item`) is caught, because the enumeration is the target. That is why the file-system seam and the OS sandbox stay underneath, and why a protection layer is best treated as one layer rather than the only one.

A parameter's value is read as a path only when it can be one. `New-Item -ItemType Directory` must not conjure a file called `Directory`, while `Remove-Item -Path C:\Windows\System32\config` must not lose its target. Both halves are pinned by tests, because that skip-list fails in two opposite directions and only one of them is noisy.
