# VPS First — VPS 初始化脚本

交互式 Linux VPS 初始化脚本，包含系统更新、用户与 SSH 配置、防火墙、Swap、fail2ban 和常用环境设置。

每个模块可以跳过。SSH 和防火墙修改会先备份，应用后要求新开终端验证；**180 秒内未确认、验证失败或脚本正常退出/收到中断信号时，会尝试回滚**。

## 运行

需要 Linux、Bash 4+、root 权限、已安装并能正常读取配置的 OpenSSH 服务端，以及交互终端。Alpine 极简镜像需要先安装 Bash。

```bash
curl -fsSL https://raw.githubusercontent.com/maodeyu180/vps_first/main/vps-init.sh -o vps-init.sh
# 阅读脚本后执行
sudo bash vps-init.sh
# 已经是 root 时: bash vps-init.sh
```

先在本地准备 SSH 公钥：

```bash
ssh-keygen -t ed25519 -C "your@email.com"
cat ~/.ssh/id_ed25519.pub
```

Windows PowerShell 查看公钥：

```powershell
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub
```

没有公钥也可以跳过配置，脚本会保留当前的认证设置。

## 执行流程

| 阶段 | 内容 |
|---|---|
| 0 | 检测发行版、权限和现有 SSH 配置 |
| 1 | 可选系统更新、EPEL 与基础工具安装 |
| 2 | 可选创建普通用户，使用独立 sudoers 文件配置权限 |
| 3 | OpenSSH 公钥解析校验、安装、实际密钥登录和 sudo 验证 |
| 4 | SSH 配置预检、备份、应用、限时验证或回滚 |
| 5 | 防火墙规则预览、备份、应用、限时验证或回滚 |
| 6 | 主机名、Swap、Locale、BBR、连接队列、fail2ban、时区、Bash 历史、自动更新 |
| 附加 | 可选从 GitHub 下载并执行 ssh_hello 安装脚本，默认跳过 |
| 7 | 配置检查与连接信息 |

## SSH 处理原则

- 密钥由 `ssh-keygen` 解析验证，拒绝只有合法外观、实际内容损坏的公钥。
- 测试命令关闭连接复用、密码和交互认证，避免旧连接或其他认证方式造成误判。验证问题默认回答 **否**。
- 只有确认密钥登录成功后，才禁用目标用户的密码及交互认证。
- 只有独立用户的密钥登录和 `sudo -v` 均已确认成功，才设置禁止 root 登录。UID 0 账号不能作为独立管理员。
- 没有完成验证时保留原认证配置，不会重新开启已禁用的密码登录。
- 本脚本的设置写入主配置开头的标记块；保留用户现有 `Include` 和 `Match`。使用 `sshd -t` 检查语法、`sshd -T -C` 检查目标用户的配置；发现条件规则覆盖认证设置则跳过修改。
- 修改端口采用**增加新端口、保留旧端口**的方式。验证稳定后再手动移除不需要的监听端口及防火墙规则。
- 检测到 `ssh.socket` / `sshd.socket` 激活时，保留现有端口。socket 的监听配置需单独处理，不能只改 `sshd_config` 就假定生效。
- SELinux 端口注册失败时跳过 SSH 修改，不会把其他服务的端口类型强行改成 SSH。

有关配置优先级和 socket 激活的说明见 [OpenSSH 手册](https://man.openbsd.org/sshd_config)及 [Ubuntu 官方说明](https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189)。

### 回滚与恢复

应用后必须保留当前终端，并在 **180 秒内**用新终端测试。超时回滚任务独立于交互输入运行；取消或读取输入失败也会触发回滚。

备份位置会在执行时打印：

| 修改 | 备份目录 | 原内容 |
|---|---|---|
| SSH | `/etc/ssh/sshd_config.vps-first.XXXXXX/` | `original` |
| 防火墙 | `/etc/vps-first-firewall.XXXXXX/` | `original/` 或 `rules.v4`、`rules.v6` |

目录中保留 `rollback.sh`、确认状态和 `rollback.log`，便于排查。已经确认的事务不会被定时任务撤销。

回滚不能覆盖机器断电、重启、所有相关进程被强制清理或备份恢复本身失败等情况。配置云安全组前应确认有控制台/VNC 入口；限时验证期间不要重启机器。

## 防火墙

优先沿用已经运行的 ufw/firewalld；发现两者同时运行时跳过自动修改。没有管理器时可使用 iptables；检测到独立 nftables 服务时跳过 iptables 修改。

- 所有规则先汇总展示，最终确认前不修改防火墙。
- 放行 sshd 配置中的全部端口，以及当前会话和新验证的端口。
- iptables 先添加 SSH、已建立连接、回环、ICMP/ICMPv6、DHCP 放行，再设置 INPUT DROP；不改 FORWARD 策略。
- firewalld 使用默认和已绑定的 zone；服务未启动时用 `firewall-offline-cmd` 预配置。保留现有 zone 策略，不强制切换到 drop。
- 现有放行规则会保留，不会自动关闭其他业务端口。HTTP/HTTPS 默认不开放。
- Arch 与 Alpine 的 iptables 使用各自的持久化路径；其他发行版使用 iptables 回退时，会提示规则尚未配置开机恢复。

firewalld 的 zone 含义见[官方说明](https://firewalld.org/documentation/man-pages/firewalld.zones)。云安全组、Docker 发布的端口和已有自定义防火墙策略仍需单独检查。

## Swap 与系统参数

没有 `/swapfile` 时，根据物理内存建议大小：≤1GB 使用两倍内存，1–4GB 使用等量，更大内存使用一半，最少 256MB。

- **已有 `/swapfile` 或同名符号链接时保留原文件**，不执行自动缩容、`swapoff` 或覆盖。
- 自动创建仅用于 ext 系列/XFS；其他文件系统提示单独处理。
- 创建后至少保留 1GB 磁盘空间；文件从开始写入时就限制为仅 root 可读写。
- 成功启用后才写入 `/etc/fstab`；失败时清理本次新建且未启用的文件。

BBR 会先检查当前内核提供的算法。可选连接队列设置为 4096；需要结合业务压测判断收益，不统一更改 TIME_WAIT、TCP 超时、临时端口范围或文件句柄上限。

参数写入 `/etc/sysctl.d/99-vps-first.conf`，按键去重，只应用当前参数。内核不支持或不允许修改的参数不会写入持久配置；不会执行 `sysctl -p` 重载其他配置。恢复时需同时恢复运行值和持久配置，单纯删除文件不会撤销当前运行值。

## 其他配置

- **sudo**：使用 `/etc/sudoers.d/90-vps-first-用户名`，写入前后用 `visudo` 检查；不依赖发行版是否默认启用 wheel 组。
- **fail2ban**：使用 `/etc/fail2ban/jail.d/99-vps-first.local`，仅配置 sshd jail，保留其他 jail；检查数字参数与配置语法，失败还原本次文件。
- **Bash 历史**：可记录时间、增加容量、追加保存；不是不可篡改的安全审计。其他 shell 不会执行 Bash 的历史命令。
- **系统更新**：Debian 使用普通升级，不自动 full-upgrade 或 autoremove。包管理器升级可能按发行版策略重启相关服务，应在合适的维护时间执行。
- **EOL 系统**：仅提供归档源地址和修复说明。不会因网络请求失败就批量改写仓库，不会关闭全局软件源有效期检查。归档源不能恢复已停止的安全维护。
- **自动安全更新**：默认关闭，支持的发行版按其更新工具配置；配置前备份已有文件。需要重启时仅提示，不主动重启机器。

## 适配与验证范围

代码包含 Debian/Ubuntu、RHEL/CentOS/Fedora/AlmaLinux/Rocky、Arch、Alpine 和 openSUSE 分支。不同版本的软件包、服务管理器和云镜像配置有差异，分支存在不代表每个版本都经过真实 VPS 验证。

本次修改已通过 Bash 语法检查、ShellCheck，以及 Debian、Alpine 本地容器各 30 项回归测试。使用真实 OpenSSH 检查配置、公钥与 Include/Match 行为；防火墙、服务重载及 Swap 等危险操作使用替身测试，验证操作顺序、拒绝路径和回滚。

容器测试不能代替真实远程登录、systemd socket、SELinux 或重启持久化验收。

## 相关项目

[ssh_hello](https://github.com/maodeyu180/ssh_hello)：可选 SSH 登录信息展示工具。

## License

MIT
