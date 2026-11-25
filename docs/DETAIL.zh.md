# 系统文件保护

阻止模型毁掉它正在工作的这台机器。

模型删掉系统文件有两条路径：直接点名文件，或者执行一条能触达它的 shell 命令。这个插件两条都判，而对"绝不能碰"的那几级，给出的是**强制拒绝**。

## 它靠什么强制

| 层级 | 做的事 | 为什么重要 |
| --- | --- | --- |
| 工具守卫 | 在调用执行前用 `ctx.tools.guard()` 返回拒绝 | 单调且与注册顺序无关：后面的监听器无法把它改回放行；即使用户批准了 `danger-full-access` 重试、操作系统沙箱已经完全失效，这道拒绝依然生效 |
| 审批通道 | `tools/pre-execute` 返回 `ask` | 看着不可逆但其实合理的操作会走到你面前确认，而不是由插件擅自决定 |
| 文件系统缝隙 | `fs/delete-intent`、`fs/write-intent`、`fs/edit-intent`，以 `prepend: true` 抢到首位 | 兜住绕过常规路径的工具；没有归属到具体调用的 Harness 内部写入一律放行。放行时仍会调用 `next()`，所以挂在同一条 waterfall 上的其它监听器（例如观察策略）照常运行 |

判定按路径分级，取最严格的一条命中。默认 **拒绝**：`system`（操作系统）、`harness`（Harness 自身与 `~/.dsh`）、`credentials`（凭据私钥）、`versionControl`（`.git` 等版本库）、`trash`（回收站与卷影副本）、家目录本身、会话工作区目录本身；默认 **询问**：用户目录（文档/桌面/下载等）、应用数据、密钥类文件、`git` 丢弃未提交改动；**不管**：依赖锁文件。每一级都可以自行设为 `deny` / `ask` / `off`。

插件读的是命令的**语义**，不是只看第一个词：嵌套的 `bash -c` / `cmd /c` / `powershell -EncodedCommand`（base64 先按 UTF-16LE 再按 UTF-8 解码）、`python -c "shutil.rmtree(...)"`、`find -delete`、`xargs`、`sudo`/`env`/`nice` 包装、`cd /etc && rm passwd`、`--` 终止符、重定向到文件与块设备、`git filter-branch` 与 `git clean` 的区别对待、通配符、`%USERPROFILE%` / `$env:SystemRoot` / `${HOME}` 展开、Windows 长路径与设备前缀（仅在 Windows 上做大小写不敏感比较），以及指向工作区之外的符号链接。它还按命令读引导链（`bcdedit`、`bootrec`、`bcdboot`、`bootsect`、`mbr2gpt`、`reagentc`、`mountvol`）、`fsutil setzerodata`、`robocopy /MIR`、`forfiles`、代码工具的源码，以及命令**要执行**的脚本正文。

对于没见过的工具（MCP、其它 bundle），只要它的名字表明会写入/删除/移动/打补丁，就会扫描其路径型参数（`path`、`file_path`、`target`、`source`、`output` 等）——因此第三方 `filesystem_remove` 删不掉 `C:\Windows`，而 `read` 同一个文件仍然正常。

## 提醒谁、怎么提醒

两个读者需要两种话术，而插件能做的事对两者并不一样。

**人** 这一侧：`userData`、`appData`、`secrets` 三级会弹出确认框。`ApprovalRequest` 只有 `agent`、`toolName`、`callId`、`reason`、`displayReason` —— 没有标题、没有严重级别、没有来源字段 —— 所以插件无法要求 Host 把自家的问题换成别的颜色或标签。文字就是全部手段。于是确认框第一行是固定的标记，接着点出级别与准确路径，并让读的人先索要一句理由，要不到就拒绝。`reason` 保持为审计用的事实句，`displayReason` 才是给人读的那份。答复是 allowed-once：插件刻意不缓存任何同意，因为一次为 `~/.ssh` 开过的绿灯，会比当初那件事活得更久。

**模型** 这一侧：通过 `ctx.systemPrompt.section()` 注册一段静态内容，order 3120 —— 排在工具说明之后、persona 后缀之前 —— 内容是这些边界、明确禁止绕路，以及要求它在发起调用之前先把理由写出来。文本保持静态，是因为装配好的提示词会作为 surface node 落进会话，只有文本变化才会替换。`modelGuidance: false` 就不注册；如果这个 profile 没有提供 `systemPrompt` 服务，插件会 warn 一句然后照常拦截。

## 1.0.0 的修是怎么来的

下面每一条都是在第二台机器上实测出来的，不是推想出来的，而且每一条现在都有测试钉住。

- **安装目录没被保护。** 它的位置只来自 `DSH_INSTALL_DIR` / `DSH_NODE_EXECUTABLE`，而这两个变量是启动器为它派生的*工具子进程*准备的；跑插件的那个进程两个都没有。打包桌面应用现在从自身内部读取——`process.versions.electron` 配上 `execPath` 与 `resourcesPath`。这个推断对普通 `node` 会拒绝采用（否则 `C:\Program Files\nodejs` 底下的每次写入都会变成拦截），对盘符根也会拒绝；macOS 下会从 `.app/Contents/{MacOS,Resources}` 上溯到 bundle。
- **`Get-Date | Format-Table` 被当成"格式化卷"拦下**，原因是黑名单是按连字符前缀匹配的。现在黑名单只精确匹配；`Format-Volume`、`mkfs.ext4` 照样拦得住。
- **隔一层赋值的写法能绕过**——`$p = 'C:\…\.git\config'; Remove-Item -LiteralPath $p`。现在命令自己赋给变量的字面量会被展开，而且判决的 notes 会记下"哪个变量展开成了什么"，于是一次拦截是可以被复核的，不是只能被信任。

拿着修好的版本再打一遍，又翻出报告里没有的两条：`rm -rf /*` 当时是按"一个通配符"判的，而不是按"根目录"判的；`-LiteralPath C:\` 的运算数整个丢了，因为分词器对 PowerShell 用了 POSIX 的反斜杠转义，而在那里 `\` 只是普通字符。这两条同样有测试，连同反向对照——`rm -rf ./out/*` 必须仍然只是清理工作区。

## 1.1.0 的修是怎么来的

第二次测评（[`system-protection-测评报告-2026-11-25.md`](system-protection-测评报告-2026-11-25.md)）是在一台 UEFI 机器上、以 `danger-full-access` 会话打的安装版 1.0.0。结论是：按路径删的覆盖得不错，**不靠路径**毁机器的路子基本没覆盖。下面每条现在都有测试钉住。

- **引导配置根本不在扫描范围里。** `bcdedit /delete {current} /f`、`bootrec /fixmbr`、`bcdboot`、`bootsect`、`mbr2gpt`、`reagentc /disable`、`mountvol S: /S`、`fsutil file setzerodata … ntoskrnl.exe` 全被放行，因为它们都没有"要删的路径"这个参数。现在按命令名与形态拒绝；只读形态（`bcdedit /enum`、`reagentc /info`、不带参数的 `mountvol`）照常放行，需要放行某条命令时用 `allowCommands`。
- **EFI 系统分区没有盘符。** `\\?\Volume{…}\EFI\Microsoft\Boot\BCD`、以及 `mountvol S: /S` 之后的 `S:\EFI\…`，都不匹配任何盘符规则。现在"引导结构"——`\EFI`、`\boot`、`\Recovery`、`\$WinREAgent`、`\System Volume Information`、别的卷上的离线 `\Windows\System32`——在**每个卷**上都被识别，卷 GUID 根本身也算卷根。
- **同一个文件有好几种写法。** 本机管理共享（`\\localhost\C$\Windows`、`\\<机器名>\ADMIN$\System32`）、8.3 短名（`C:\PROGRA~1`）、`subst` 盘符、目录 junction，现在都会被解析成真实路径再判，取最严格的结果。Node 普通的 `realpathSync` 不会展开 8.3 短名，所以解析用的是 native 版本。别的机器上的共享仍然当网络路径处理。
- **`cmd /c "cd /d … && del 相对路径"` 把运行目录移到了 `C:\d`。** `cd` 的读取现在会跳过 cmd 的 `/` 开关，相对删除目标落在真正进入的目录下；分词器也不再在 cmd/PowerShell 里把反斜杠当转义（在那里它只是路径字符）。
- **脚本被当成数据。** `pwsh -File .\cleanup.ps1` 无论脚本里写什么都不拦。现在命令**要执行**的本地脚本会先被读取（上限 256 KiB、最多 8 个文件、绝不列目录）并扫描，然后才放行。这是插件唯一读取文件内容的地方，`scanScripts: false` 可以关掉，`test/no-touch.mjs` 钉死"只读这一个脚本"。
- **`robocopy /MIR`、`forfiles /c "cmd /c del @path"`、`sdelete`、复制类命令的目标**都会被识别：镜像就是把源里没有的东西全删掉。
- **代码工具不是 shell。** `run_code` / `execute_code` / REPL 类工具现在按"代码"读：识别文件 API 调用与字面 `exec("…")` 字符串，但不会把普通源码丢给 shell 分词器（所以源码里的 `format(x)` 不会被当成"格式化卷"）。
- **插件能在会话里被关掉。** `plugin_manager` / `plugin_market` 的豁免保留，只多判一种调用：点名本插件并禁用它/卸载它——直接拒绝（`PROTECTED_SELF`）。`selfProtect: false` 是给使用者的开关。
- **内部错误以前是放行的。** `onInternalError` 现在默认 `closed`，工具守卫与文件系统缝隙都一样：判定不出来就拒绝，而不是放过去。


## 插件绝对不会做的事

- 它自己从不删除、移动或改写任何文件；唯一可能写入的是你自行配置的审计日志。
- 它只读一种文件内容：工具调用**点名要执行**的脚本（`pwsh -File x.ps1`、`bash ./build.sh`、`python x.py`），每个最多 256 KiB、最多 8 个，绝不列目录，`scanScripts: false` 可关。除此之外对文件系统只有 `existsSync` / `lstatSync` / `statSync` / `realpathSync`，且只用在调用已经点名的路径上，用来解析符号链接、盘符与 8.3 短名。
- 它不起任何进程，不开任何网络连接。
- 它的作用范围只有 DSH 这个进程。它挂的是 DSH 的工具管线与 DSH 的文件系统缝隙；不是 DSH 的程序既不受它约束，也影响不到它 —— 它看不到机器上其它任何东西。
- 它给出的判定是数据，不是动作：守卫的拒绝是一个返回对象，文件系统层的拒绝是一次抛错。什么也不会被它执行。
- 不联网，不采集任何遥测。
- 它不会干涉插件管理器对其它 bundle 的日常管理；唯一拒绝的是"在会话里把本插件关掉/卸载"这一种调用（`selfProtect: false` 可以连这条也关掉）。
- 不干涉未归属到工具调用的 Harness 内部文件操作。

`test/no-touch.mjs` 在运行时逐条验证上面这些说法：把 `node:fs`、`node:fs/promises`、`node:child_process`、`node:net`、`node:http` 上的每个函数换成记录代理（写型调用直接抛错），再让插件跑完三层的全部恶意调用，断言期间没有发生任何写入、没有列目录、唯一的内容读取是调用自己点名的那个脚本、没有起进程、没有开连接，并且环境变量、工作目录、信号监听数、活跃句柄数全部保持原样。

## 如果被拦下了、但你认为不该拦

拒绝信息里会写明命中的级别与具体路径。接下来按推荐顺序：

1. 改在会话工作区内操作，或把这件事交给人工来做。
2. 把这一个路径加入 `allowExtra`（它高于所有级别，包括 `system`）。
3. 调低该级别：`tiers: { appData: "off" }`。
4. 只给某个工具或命令开后门：`sweepSkipTools`、`exemptTools`；没有路径可点的命令（如 `mountvol`）用 `allowCommands`。
5. 先设 `enforcement: "audit"`，只看它会拦什么，确认可信后再打开强制。

`/system-protection status` 查看当前级别表与计数；`/system-protection test <命令或路径>` 演练单次调用，不执行任何操作。

有一个后果值得知道：`~/.dsh` 与当前 profile 属于 `harness` 级，所以工具想去改 Harness 自己的状态文件或补丁文件会被拒 —— 这是刻意的，那里存的是 Harness 自己的配置。确实需要时，把那一个文件写进 `allowExtra`。

反过来的情形也值得知道，它是真实会话里撞出来并已修掉的：插件会保护自己的源码，免得模型把保护层本身删掉来解除限制。但当插件目录正好落在会话工作区内部 —— `link:` 安装且正在开发时就是这个形状 —— 这条规则会把整棵树里的正常编辑一并拦下，所以它此时让位给工作区，并在启动日志里明确说明自我保护已暂停。系统、凭据、Harness、版本控制这些根的保护不变；正常安装的副本在 profile 目录下，仍由 `harness:profile` 守着。

## 已知边界

对 shell 的检查本质是对文本的分析，而文本是可以闪避的：由更早的变量拼出来的路径、通过 `& $path` 或 `Invoke-Expression (Get-Content …)` 间接执行的脚本、运行时下载的载荷，或内部自行解析目标的程序，都可能绕过扫描。命令**点名要执行**的脚本会被读取并扫描（1.1.0），这堵住了"先写一个 .ps1 再运行它"的两步路，但它仍然是在读文本。所以文件系统缝隙与操作系统沙箱仍在下面兜底；也正因为如此，任何保护都应当被当作其中一层，而不是唯一一层。

参数的值只有在可能是路径时才当作路径：`New-Item -ItemType Directory` 不能凭空造出一个名叫 `Directory` 的文件，而 `Remove-Item -Path C:\Windows\System32\config` 也绝不能把真正的目标丢掉。这两个方向都有测试钉住 —— 那份跳过清单会朝两个相反的方向出错，而其中只有一种会吵闹。
