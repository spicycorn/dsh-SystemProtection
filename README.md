# System file protection (`@local/system-protection`)

A [DeepSeek Harness](https://github.com/deepseek-ai) bundle that **forcibly stops the model from deleting or overwriting files whose loss would break the operating system, the Harness itself, your credentials, or your version control history.**

It is a guard, not a suggestion. The model cannot argue with it, cannot re-allow itself, and cannot bypass it by escalating its own file permissions — the denial happens in the tool pipeline, which sits *above* the OS sandbox.

```
DENY  system  (operating system)  system:windows
      target: C:\Windows\System32
Do what is safe instead: work inside the session workspace, back the file up or move it to a
trash folder first, or ask the user to remove it by hand.
Do not rephrase the command to get around this protection.
```

## What is protected, and how

| Tier | Examples | Default |
| --- | --- | --- |
| `system` | `%SystemRoot%`, `C:\Program Files`, `/etc`, `/usr`, `/bin`, `/boot`, `/dev`, `/System`, volume roots (`C:\`), `ntuser.dat`, `pagefile.sys`, `/dev/sda`, format/`diskpart`/`mkfs` | **deny** |
| `harness` | the DSH install directory, `~/.dsh`, the active profile directory, this plugin's own files | **deny** |
| `credentials` | `~/.ssh`, `~/.gnupg`, `~/.aws`, macOS keychains, `LSA Secrets`, `SAM`, `NTDS.dit` | **deny** |
| `versionControl` | any `.git` / `.svn` / `.hg` tree, `git filter-branch`, `git gc --prune=now` | **deny** |
| `trash` | Recycle Bin, `~/.Trash`, XDG trash, `Clear-RecycleBin`, `vssadmin delete shadows` | **deny** |
| `homeRoot` | your home directory itself, `/home`, `rm -rf ~` | **deny** |
| `workspaceRoot` | the session workspace directory itself (`rm -rf .`, `rm -rf ..`) — its *contents* stay free | **deny** |
| `userData` | `Documents`, `Desktop`, `Downloads`, `Pictures`, `Music`, `Videos`, `C:\Users\Public` | ask |
| `appData` | `%APPDATA%`, `%LOCALAPPDATA%`, `~/Library`, XDG config/data/cache — one application's folder, not one setting file | ask |
| `secrets` | `.env`, `*.pem`, `*.key`, `id_ed25519`, `.npmrc`, `.git-credentials`, `credentials.json` | ask |
| `uncommittedWork` | `git clean -fdx`, `git reset --hard`, `git checkout .` | ask |
| `lockfiles` | `package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum` | off |

Three independent layers enforce this:

1. **`ctx.tools.guard()`** — a monotonic denial on the tool pipeline. It cannot be undone by a listener registered later, and it still runs when the user approved a `danger-full-access` retry (the exact moment the OS sandbox stops helping).
2. **`tools/pre-execute`** — the `ask` tier routes through the Harness approval flow, so an irreversible-looking delete needs a human click.
3. **`fs/delete-intent` / `write-intent` / `edit-intent`** — the deepest seam any tool can reach, registered with `prepend: true` so this plugin holds the single decision slot. Only calls the Host attributes to something are judged; Harness-internal file writes pass through.

It reads *shell text*, not only file paths: `rm`, `del`, `rd`, `Remove-Item`, `mv`, `mvn`-style moves, `find -delete`, `find -exec rm`, `xargs`, redirections (`> file`, `dd of=/dev/sda`), truncation, `git` history operations, `powershell -EncodedCommand` (base64 → UTF-16LE → UTF-8), nested `bash -c` / `cmd /c` payloads, `python -c "shutil.rmtree(...)"`, `sudo`/`env`/`nice` wrappers, `cd X && rm y`, `--` separators, globs, `$env:VAR` / `${HOME}` / `%USERPROFILE%` expansion, `\\?\C:\` extended prefixes, and symlinks pointing outside the workspace. Unknown MCP tools are swept for path-shaped arguments (`path`, `file_path`, `target`, `source`, `output`, …) whenever their name says they write or delete.

Version 1.1.0 answers the attacks in [`docs/system-protection-测评报告-2026-11-25.md`](docs/system-protection-测评报告-2026-11-25.md):

- **The boot chain, by command rather than by path.** `bcdedit` (any mutating form), `bootrec /fixmbr` / `/fixboot` / `/rebuildbcd`, `bcdboot`, `bootsect`, `mbr2gpt`, `reagentc /disable`, `mountvol /S` and `fsutil file setzerodata` are denied by their own name and form. Read-only forms (`bcdedit /enum`, `reagentc /info`, `mountvol`) still pass.
- **The EFI system partition is protected without a drive letter.** Slices of a volume — `\\?\Volume{…}\EFI\…`, `\EFI`, `\boot`, `\Recovery`, `\$WinREAgent`, `\System Volume Information`, an offline `\Windows\System32` — are judged on *every* volume, so `mountvol S: /S` and then `del S:\EFI\…` is still a denial.
- **One file, several spellings.** This machine's administrative shares (`\\localhost\C$\Windows` and `\\<computer-name>\ADMIN$\System32`), 8.3 short names (`C:\PROGRA~1`), `subst` drive letters and junctions are resolved and judged as the path they really are. A share on another machine stays a network path.
- **A script is a shell in disguise.** When a command would *run* a local script (`pwsh -File x.ps1`, `bash ./build.sh`, `. .\profile.ps1`, `python tools/x.py`, `cmd /c x.bat`), the file is read — bounded to 256 KiB, at most 8 files, never a directory listing — and scanned before it runs. `scanScripts: false` turns this off.
- **`cmd /c "cd /d … && del relative"` resolves against the new directory**, and `robocopy /MIR`, `forfiles /c "del @path"` and copy destinations are recognised as destructive.
- **Code tools are read as code.** `run_code` / `execute_code` / REPL-style tools are scanned for file-API calls (`shutil.rmtree("C:\\Windows")`, `fs.rmSync(…)`) and literal `exec("…")` commands.
- **The guard cannot be switched off from inside the session.** `plugin_manager` and `plugin_market` stay exempt except for a call that names this plugin and disables or removes it.
- **The plugin fails closed.** `onInternalError` now defaults to `closed`, on the tool guard and on the file-system seam.


## Install

The plugin is **not** installed by this repository; you install it. Verified against the current desktop build's plugin page.

1. Put the source somewhere stable — it is symlinked from the profile, so do not leave it in a temp folder. Example: `C:\projects\dsh_plugins\dsh-SystemProtection`.
2. In the sidebar open **Plugins** (插件) → **Add plugin** (添加插件). The arrow next to the button also offers **Install a third-party plugin** (安装第三方插件); both open the same dialog.
3. Paste an absolute path, with the `link:` prefix, into the spec field:

   ```text
   link:C:\projects\dsh_plugins\dsh-SystemProtection
   ```

   A bare absolute path is accepted too, and so are `file:`, a package name, a Git URL or a `.tgz`. `link:` is what the harness itself uses for development directories, and it means the installed bundle *is* this directory: edit a file here, reload, and the change is live.
4. The dialog checks the spec first (`pluginManager.inspect` reads the local `package.json`): a missing package, or one without a `dsh.bundle` patch, is refused in one line before anything is downloaded. Then **Install** (安装) runs, and finishes with **Enable now** (立即启用). Declining leaves it installed but switched off. If the Host reports the change needs a restart, restart DeepSeek Harness.
5. Confirm it is live: `/system-protection status` should print `system-protection: enabled, enforce` and the tier table.
6. Prove a denial without risking anything: `/system-protection test rm -rf C:\Windows` prints `DENY … system …` and executes nothing.
7. Prove it end to end. In a session, ask the model to write a string to a file that does not exist yet:

   ```text
   用 write 工具把 ok 写入 C:\Windows\System32\__dsh_probe__.txt，然后告诉我结果
   ```

   The call comes back failed with the `system-protection` / `PROTECTED_PATH` reason and the `system` tier named, and `/system-protection status` shows `denied 1`. Worst case, if the plugin were somehow not enforcing, DSH's own OS sandbox refuses the write as well, and the only artefact would be one stray file you can delete.

To turn it off or take it out: the bundle switch on its page (a `config: { enabled: false }` edit does the same thing), or **Uninstall** (卸载) with its confirmation. `plugin_manager` and `plugin_market` stay exempt so you can always manage bundles — the one exception is a call that names *this* plugin and disables or uninstalls it while it is running, which the model must not be able to do from inside a session (`selfProtect: false` removes even that check).

If you already maintain a profile patch, copy the row from [`cordis.patch.yml`](cordis.patch.yml) into it once the package is resolvable; the row id is `system-protection`.

### If the card says the plugin failed

A plugin that throws during activation does not protect anything — it only shows a diagnostic. Open the bundle and look at the row's state (`plugin_manager ▸ list_plugins` reports it as `fiberPhase: "failed"` with a `diagnostic` sentence). One such failure really happened during development and is worth naming, because its symptom is silence:

```text
cannot get property "sandboxPolicy" without inject
```

Cordis answers a `ctx.<service>` property read for any service the plugin did not declare in `inject` by throwing, so a `?? fallback` written after such a read is dead code and the fiber dies before a single guard is registered. The plugin therefore reads every optional service through `ctx.get(name)` — the documented way to read a service without the inject requirement — and `test/host.mjs` reproduces the Host's rule, including a check that the rule is not vacuous. If you write your own plugin, that one line is worth the whole lesson.

## Configuration

Everything lives in the row's `config` (see the commented block in [`cordis.patch.yml`](cordis.patch.yml)) — the plugin registers no settings page of its own, so the patch file is where you edit it. Values are validated at activation; a typo is reported in the Host log and the default is kept, never silently widened.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Register nothing at all when false. |
| `enforcement` | `enforce` | `audit` logs the verdicts it *would* enforce and lets the call through. |
| `tiers` | table above | Per-tier action: `deny`, `ask`, or `off`. |
| `protectWrites` | `true` | Overwriting a protected file is treated like deleting it. |
| `scanShell` | `true` | Read the text of `bash` / `pwsh` / `terminal_send` commands. |
| `scanScripts` | `true` | Read (≤ 256 KiB, ≤ 8 files) a local script a command would run, and scan it first. |
| `selfProtect` | `true` | Even an exempt tool cannot disable or uninstall this plugin. |
| `genericPathSweep` | `true` | Sweep path arguments of unknown write/delete tools. |
| `sweepTools` / `sweepSkipTools` | `[]` | Force the sweep on, or exempt a tool name from it. |
| `exemptTools` | `plugin_manager`, `plugin_market` | Tools that must be able to manage this very plugin (still subject to `selfProtect`). |
| `protectExtra` | `[]` | Your own prefixes to protect, `~`/`%ENV%` allowed. |
| `allowExtra` | `[]` | Your own escape hatch; beats every tier, including `system`. |
| `allowCommands` | `[]` | Commands you permit by name (`mountvol`, `bcdboot`, …). A form-only denial names no path, so `allowExtra` cannot open it. |
| `resolveSymlinksInsideWorkspace` | `false` | Also `realpath` links that live inside the workspace (slower, stricter). |
| `auditLog` | `""` | Absolute path; append one JSON line per non-allow decision. |
| `denyNote` | `""` | Extra sentence added to every message, e.g. where backups live. |
| `onInternalError` | `closed` | `closed` denies calls when the plugin itself throws; `open` lets them through. |
| `messageLocale` | `auto` | `auto` \| `en` \| `zh`. |
| `modelGuidance` | `true` | Contribute one short system-prompt section telling the model these limits exist and to state its reason before touching those paths. |

## The confirmation card

Three tiers end in a question to you instead of a block: `userData` (Documents, Desktop), `appData`, and `secrets` (`.env`, `.npmrc`, `id_rsa`, `.git-credentials`). Those questions arrive through the same approval mechanism as any other permission prompt, and `ApprovalRequest` has **no title, severity, or source field** a plugin could set — so the plugin cannot ask the UI to colour it differently. The text is the only lever, and it is written to be unmistakable:

```text
⚠ SYSTEM PROTECTION plugin — this is NOT a routine permission request
This call would change a protected location, and it needs your judgement now.
  · secret file (.env, *.key, id_rsa, …) [delete] C:\Users\you\.npmrc
Before approving, ask the AI for one sentence: why this location has to change, and
what is lost if it goes wrong.
If it cannot answer concretely, reject.
```

The same rule is given to the model in advance (`modelGuidance`), so the reason should already be in its reply *before* the card ever appears — the card is then a check on an explanation you have already read, not the first time anyone mentions it. Approvals here are one-shot by design: the Host grants `allowed-once` per question, and the plugin deliberately does not cache your answer, because a remembered yes for `~/.ssh` is exactly the kind of thing that outlives the task that justified it.

## Commands

- `/system-protection status` — enabled state, tier table, counters, last decisions, resolved protected roots.
- `/system-protection test <command or path>` — dry run: shows the tier and action a call *would* get, executes nothing.
- `/system-protection reset` — clear counters and the recent list.

## Limits, honestly

- Shell inspection is text analysis. What the command assigns to its own variables **is** resolved — `$p = 'C:\…\.git\config'; Remove-Item $p` is denied, and the verdict says so in its notes — because the plugin reads the literals the command itself puts on the table. What it cannot resolve stays honestly open: a value from `Read-Host` or a prompt, a string built at runtime (`"$env:SystemRoot\x"`, `-f` formatting), `Invoke-Expression` / `& $p`, a payload downloaded and run, or a variable set by an *earlier* call. A compiled helper taking an index into a table can hide a target too.
- A script the command *runs* is scanned (1.1.0), but only when the command names it in a form the scanner recognises: `pwsh -File x.ps1`, `bash ./x.sh`, `. .\x.ps1`, `python x.py`, `cmd /c x.bat`, or the script itself as the command. A script reached through `& $path`, `Invoke-Expression (Get-Content x)`, a downloaded payload, or a program that decides internally what to run is still outside text analysis. The file-system layer (3) and the OS sandbox stay underneath all of it.
- The scanner follows the shell rather than guessing intent. `Remove-Item D:\My App\file.txt`, unquoted, is two arguments to PowerShell and it deletes neither, so the plugin sees two arguments as well. Quote paths that contain spaces.
- Wiping a filesystem root is denied in every spelling the tests can think of: `rm -rf /`, `rm -rf /*`, `rm -rf ~/*`, `Remove-Item C:\ -Recurse`, and the same hidden behind a variable. A glob inside your workspace (`rm -rf ./out/*`) is still just cleanup.
- The application directory is protected as `harness`. It comes from `DSH_INSTALL_DIR` / `DSH_NODE_EXECUTABLE` when the launcher exports them, and otherwise from the running process itself (a packaged desktop app knows its own executable and `resources` directory). Two edges are left open on purpose: a plain `node` process never makes its own tree the install — that would deny every `npm install` under it — and an app installed *directly on a drive root* is not inferred, because protecting a whole volume by accident is worse than the miss it trades. Both cases are one `protectExtra` line.
- A harness root that **contains** the session workspace yields to it. If you point a session at the Harness install, `~/.dsh`, or the profile directory, the plugin assumes you mean to work there; `system`, `credentials`, and `versionControl` never yield, so such a session still cannot delete `C:\Windows`.
- The guard is one layer of defence. Keep `danger-full-access` off unless a task needs it, keep backups, and keep `git` clean.
- `allowExtra` is absolute: it exists so that "yes, really delete that" is one config line, not a code change.
- Because `~/.dsh` and the active profile directory are in the `harness` tier, a tool call that tries to edit Harness's own state or patch file is denied. That is deliberate — the model should not be rewriting the harness config behind your back — but if you *want* it to, name the exact file: `allowExtra: ["~/.dsh/profiles/desktop/cordis.patch.yml"]`.
- The plugin normally guards **its own files** too, so a model cannot delete the protection to switch it off. The exception is the general one above: when a harness root — the plugin's own directory, the install, `~/.dsh`, the profile — sits inside the session workspace, it steps aside for that workspace, and the startup log says so out loud. A normal `link:` install is not inside the session workspace it protects, so in practice the plugin stays guarded; when it does live in the workspace someone is editing, their own tree wins and the log names the trade.
- Shell parsing reads a switch's value as a path only when it could be one. `New-Item -ItemType Directory`, `Set-Content -Encoding UTF8`, `-ErrorAction SilentlyContinue` contribute no operands; `Remove-Item -Path` / `-LiteralPath` and friends always do. Both directions are pinned by tests, because the wrong entry in that skip-list would hide a real target instead of just producing noise.
- Nothing is uploaded anywhere. No network access, no telemetry; the only optional write is the audit log you name.

## Can the plugin itself damage the system?

No, and this is measured rather than promised. The plugin's entire interaction with the machine is: answer a DSH call with allow / ask / deny, log a line, and (only if you configure it) append to that one audit file.

| Surface | Reality |
| --- | --- |
| File writes | One: `fs.appendFileSync` to the `auditLog` path you set. Off by default → zero writes. |
| File reads | Exactly one kind, added in 1.1.0: the text of a *script the call itself names to run* (`pwsh -File x.ps1`, `bash ./build.sh`, `python tools/x.py`), bounded to 256 KiB and eight files, never a directory listing, and switched off with `scanScripts: false`. Nothing else is ever read. |
| Metadata lookups | `existsSync` / `lstatSync` / `realpathSync` on exactly the paths a call named (to resolve symlinks, drives and 8.3 names). Metadata only, no content. |
| Processes | None. `node:child_process` is not imported. |
| Network | None. No `http` / `net` / `dns` / `tls` / `fetch`. |
| Global state | No signal handlers, no timers, no `process.env` writes, no `chdir`, no prototype patching. Disposing the plugin removes its guard and listeners. |
| Reach | In-process only. It hooks DSH's tool pipeline and DSH's file-system seam, so it cannot affect any program other than DSH, and cannot see anything outside the calls DSH routes to it. |
| Self-defense | It answers `plugin_manager` / `plugin_market` normally, except a call that names this plugin and disables or uninstalls it — the one action that would leave the machine unprotected mid-session. That check has its own switch (`selfProtect: false`). |

`npm test` includes `test/no-touch.mjs`, which replaces every function on `node:fs`, `node:fs/promises`, `node:child_process`, `node:net`, and `node:http` with a recording proxy, throws on any write-shaped call, then runs the plugin through 25 hostile calls across all three layers and the three commands. It asserts: zero mutating calls, no directory listing, the only content read is the script the call named, zero spawns, zero sockets, unchanged `process.env` / `cwd` / signal listeners / active handles — and in the opt-in phase, that the single write lands exactly on the configured audit path via an append flag.

### What it costs a session

The guard is synchronous and cheap, and `test/perf.mjs` keeps it that way (measured on a Windows laptop, one tool call):

| Input | Cost | Verdict |
| --- | --- | --- |
| `rm -rf ./build && echo done` | 0.6 ms | allow |
| 20 000 chained segments, all safe | 462 ms | allow |
| 1 MB of benign command text | 530 ms | allow |
| 20 000 chained segments, one of them hostile | 92 ms | deny |
| 60 nested `bash -c`, hostile target inside | 0.7 ms | deny |

Cost is linear in the size of the argument, and scanning stops at the first operand that reaches a `deny` tier — the verdict cannot get stricter after that. A megabyte-long single command is half a second, which a shell launch swallows anyway.

## Development

```bash
npm test          # 175 decision checks + 44 wiring + 18 no-touch + 10 performance + 13 packaging checks
```

- `test/selftest.mjs` — simulated Windows and Linux machines, no install, no network.
- `test/fake-host.mjs` — runs the real `apply()` against a stub of the Cordis services the plugin touches (guard, pre-execute, fs intents, commands, effects), on the machine you are on.
- `test/no-touch.mjs` — the audit above: proves the plugin answers, and does not act.
- `test/perf.mjs` — pathological inputs against latency budgets, so the guard never becomes the slow part of a session.
- `test/host.mjs` — the stub Host both suites drive.
- `tools/asar-search.js` — the inspection helper used while writing this: bounded literal search inside an ASAR (`SEARCH_ALL=1 node tools/asar-search.js <dir> <term>`).
- `tools/peek-dir.mjs` / `tools/check-yaml.mjs` — list a directory inside the installed build, and parse this bundle's patch through the packaged YAML reader. Both need the DSH-bundled Node (`tools/run-node.ps1`), because only it can read inside `app.asar`.

MIT licensed. See [docs/DETAIL.md](docs/DETAIL.md) (English) and [docs/DETAIL.zh.md](docs/DETAIL.zh.md) (简体中文) for the plugin detail page.
