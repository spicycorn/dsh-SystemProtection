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

The plugin reads the *meaning* of a command, not just its first word: nested `bash -c` / `cmd /c` / `powershell -EncodedCommand` payloads (base64 decoded as UTF-16LE then UTF-8), `python -c "shutil.rmtree(...)"`, `find -delete`, `xargs`, `sudo`/`env`/`nice` prefixes, `cd /etc && rm passwd`, `--` terminators, redirections onto files and block devices, `git filter-branch` versus `git clean`, globs, `%USERPROFILE%` / `$env:SystemRoot` / `${HOME}` expansion, Windows extended-length and device prefixes, case-insensitive comparison on Windows only, and symlinks that point outside the workspace.

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

## What the plugin never does

- It never deletes, moves, or rewrites anything itself. The only file it may write is an audit log you configure.
- It never reads a file: no `readFile`, no directory listing, no file handles. The only file-system calls it makes are `existsSync` / `lstatSync` / `realpathSync` on paths a call already named, to resolve symlinks.
- It never starts a process and never opens a socket.
- Its reach is the DSH process only. It hooks DSH's tool pipeline and DSH's file-system seam; programs that are not DSH are outside its world in both directions — it cannot restrict them, and it cannot be affected by them.
- The verdicts it produces are data, not actions: a guard denial is a returned object, a file-system denial is a thrown error. Nothing is carried out.
- It never contacts the network and collects no telemetry.
- It never blocks the Plugin Manager from removing this plugin, so you can always turn it off.
- It never touches Harness-internal file operations that are not attributed to a tool call.

`test/no-touch.mjs` asserts exactly these claims at run time by replacing `node:fs`, `node:fs/promises`, `node:child_process`, `node:net` and `node:http` with recording proxies that throw on writes, then driving the plugin through hostile calls on all three layers.

## If you are blocked and should not be

The denial message names the tier and the exact path. Then, in rough order of preference:

1. Work inside the session workspace, or ask for the operation to be done by a human.
2. Add the one path to `allowExtra` (it beats every tier, including `system`).
3. Lower the tier: `tiers: { appData: "off" }`.
4. Widen the escape hatch for one tool: `sweepSkipTools`, `exemptTools`.
5. Set `enforcement: "audit"` to watch what it *would* block before trusting it.

`/system-protection status` shows the live tier table and counters; `/system-protection test <command or path>` dry-runs a single call.

One consequence worth knowing: because `~/.dsh` and the active profile are in the `harness` tier, a tool call that tries to edit Harness's own state or patch file is denied — deliberately, since that is where the harness keeps its own configuration. If you want that for one specific file, name it in `allowExtra`.

The reverse case, which was found in a real session and is now handled: the plugin guards its own source so a model cannot delete the protection to switch itself off. When the plugin's directory sits *inside* the session workspace — the normal shape of a `link:` install someone is developing — that rule would deny every ordinary edit in the tree, so it yields to the workspace and the startup log warns that self-protection is off. Protection of the system, credential, Harness and version-control roots does not change, and a normally installed copy (under the profile) stays guarded by `harness:profile`.

## Known limits

Shell inspection is analysis of text, and text can be evasive: a path assembled from variables set earlier, a script written to disk and then executed, or a program that resolves its target internally can hide from the scanner. That is why the file-system seam and the OS sandbox stay underneath, and why a protection layer is best treated as one layer rather than the only one.

A parameter's value is read as a path only when it can be one. `New-Item -ItemType Directory` must not conjure a file called `Directory`, while `Remove-Item -Path C:\Windows\System32\config` must not lose its target. Both halves are pinned by tests, because that skip-list fails in two opposite directions and only one of them is noisy.
