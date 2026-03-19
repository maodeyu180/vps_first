# VPS First —  VPS 到手后的第一个脚本

> 新买的 VPS 就像一扇没上锁的门，全世界的脚本小子都在敲。这个脚本帮你把门锁好。

一个**安全优先、多发行版兼容**的 VPS 初始化脚本，覆盖从裸机到安全可用的完整流程。

## 特性

- **多发行版兼容** — Debian/Ubuntu、CentOS/RHEL/Fedora/AlmaLinux/Rocky、Arch、Alpine、openSUSE
- **防锁定设计** — 禁用密码登录前强制验证密钥登录，SSH 配置修改失败自动回滚
- **公钥格式校验** — 粘贴公钥时自动验证格式，防止无效密钥写入
- **EOL 源自动修复** — CentOS/Debian/Ubuntu/Fedora EOL 后自动切换到对应归档源
- **SELinux 自适应** — CentOS/RHEL 修改端口时自动处理 SELinux 策略
- **防火墙自动选择** — 根据系统自动使用 ufw / firewalld / iptables
- **全程可交互** — 每个步骤都可确认或跳过，不会强制执行

## 执行流程

```
阶段 0  前置检查          → 系统检测、发行版识别、适配方案确认
阶段 1  系统更新          → 软件包更新 + 基础工具安装 (+ EPEL 源)
阶段 2  用户配置          → 可选创建非 root 用户 + sudo 权限
阶段 3  SSH 密钥          → 公钥安装 + 格式校验 + ⚠️ 登录验证
阶段 4  SSH 加固          → 改端口 / 禁 root / 禁密码 + ⚠️ 登录验证 + 自动回滚
阶段 5  防火墙            → ufw / firewalld / iptables 自动选择
阶段 6  系统优化          → 6.1 主机名
                          → 6.2 Swap 虚拟内存 (自动推荐大小)
                          → 6.3 Locale 语言环境
                          → 6.4 BBR 加速 + 内核网络调优
                          → 6.5 fail2ban 防暴力破解
                          → 6.6 系统时区
                          → 6.7 命令历史增强 (安全审计)
                          → 6.8 自动安全更新
附加    SSH Hello         → 可选安装 SSH 登录美化脚本
阶段 7  总结              → 13 项检查清单 + 连接信息 + SSH Config 建议
```

## 快速开始

### 一键运行（推荐）

**海外服务器：**

```bash
curl -fsSL https://raw.githubusercontent.com/maodeyu180/vps_first/main/vps-init.sh -o vps-init.sh && sudo bash vps-init.sh
```

**国内服务器：**

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/maodeyu180/vps_first/main/vps-init.sh -o vps-init.sh && sudo bash vps-init.sh
```

### 手动下载运行

```bash
# 下载
wget https://raw.githubusercontent.com/maodeyu180/vps_first/main/vps-init.sh

# 添加执行权限
chmod +x vps-init.sh

# 以 root 身份运行
sudo bash vps-init.sh
```

## 运行前准备

你只需要准备一样东西：**SSH 公钥**。

如果还没有，在你的**本地电脑**上生成：

```bash
ssh-keygen -t ed25519 -C "your@email.com"
```

然后查看公钥内容，脚本运行时需要粘贴：

```bash
# Linux / Mac
cat ~/.ssh/id_ed25519.pub

# Windows PowerShell
cat $env:USERPROFILE\.ssh\id_ed25519.pub

# Windows CMD
type %USERPROFILE%\.ssh\id_ed25519.pub
```

> 没有公钥也能运行，脚本会自动跳过密钥相关配置，并保持密码登录开启。

## 安全机制

本脚本的核心原则是 **永远不锁死用户**：

| 风险场景 | 保护措施 |
|---------|---------|
| 公钥粘贴错误 | 格式校验 (ed25519/rsa/ecdsa)，错误允许重试 3 次 |
| 密钥登录不通 | 强制要求新开终端实测，失败则不禁用密码 |
| SSH 配置写坏 | `sshd -t` 语法检查，失败自动回滚备份 |
| 改端口后连不上 | 再次要求实测，失败自动还原并重启 SSH |
| SELinux 阻拦 | 自动 `semanage` 注册端口 + `restorecon` 修复上下文 |
| 防火墙锁端口 | 可选同时保留 22 端口作为 fallback |

## 发行版兼容性

| | Debian/Ubuntu | CentOS/RHEL | Fedora | Alma/Rocky | Arch | Alpine | openSUSE |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 包管理器 | apt | yum/dnf | dnf | dnf | pacman | apk | zypper |
| 防火墙 | ufw | firewalld | firewalld | firewalld | iptables | iptables | firewalld |
| sudo 组 | sudo | wheel | wheel | wheel | wheel | wheel | wheel |
| SELinux | — | 自动处理 | 自动处理 | 自动处理 | — | — | — |
| EPEL 源 | — | 自动安装 | 不需要 | 自动安装 | — | — | — |
| 自动更新 | unattended-upgrades | dnf-automatic | dnf-automatic | dnf-automatic | 提示手动 | 提示手动 | YaST |

## 各模块说明

### Swap 虚拟内存

根据物理内存自动推荐 Swap 大小：

| 物理内存 | 推荐 Swap | 理由 |
|---------|----------|------|
| ≤ 1 GB | 2 倍内存 | 低配 VPS 必须有 Swap |
| 1-4 GB | 等量 | 平衡方案 |
| > 4 GB | 一半 (最小 2GB) | 大内存不需要太多 Swap |

同时会设置 `swappiness=10`（尽量用物理内存）和 `vfs_cache_pressure=50`（减少缓存回收压力）。

### 内核网络调优

可选开启，适合跑 Web 服务 / 反向代理的 VPS：

| 参数 | 值 | 作用 |
|-----|-----|------|
| `net.core.somaxconn` | 65535 | 增大 TCP 连接队列 |
| `net.ipv4.tcp_tw_reuse` | 1 | 复用 TIME_WAIT 连接 |
| `net.ipv4.tcp_fin_timeout` | 15 | 加快连接回收 |
| `net.ipv4.tcp_fastopen` | 3 | 开启 TCP Fast Open |
| `net.ipv4.ip_local_port_range` | 1024-65535 | 扩大可用端口范围 |
| `fs.file-max` | 1048576 | 提高文件描述符上限 |

### 命令历史增强

为所有用户启用，每条命令记录执行时间，方便安全审计：

```
  496  2026-03-19 14:30:15  apt update
  497  2026-03-19 14:31:02  systemctl restart nginx
```

保留 10000 条历史记录，多终端同时写入不会互相覆盖。

## 完成后你会得到

脚本结束时会输出一份完整的检查清单和连接信息：

```
===== 系统检查清单 =====

  ✓ 主机名: my-vps
  ✓ 用户 'deploy' (sudo 组)
  ✓ SSH 公钥已配置
  ✓ 密码登录已禁用
  ✓ Root SSH 已禁止
  ✓ SSH 端口: 22000
  ✓ Swap: 2048MB
  ✓ 防火墙已启用 (ufw)
  ✓ BBR 加速已开启
  ✓ fail2ban 运行中
  ✓ 时区: Asia/Shanghai
  ✓ Locale: en_US.UTF-8
  ✓ 命令历史增强已配置

得分: 13/13

===== 连接信息 =====

  登录命令:
    ssh -p 22000 deploy@你的IP

===== 本地 SSH Config 建议 =====

  Host my-vps
      HostName 你的IP
      User deploy
      Port 22000
      IdentityFile ~/.ssh/id_ed25519
```

## 附加功能：SSH Hello

脚本最后会询问是否安装 [ssh_hello](https://github.com/maodeyu180/ssh_hello) — 一个 SSH 登录信息美化脚本。

安装后每次 SSH 连接会自动显示：

- 自定义 ASCII 艺术字 Banner
- 服务器状态（CPU / 内存 / 磁盘 / 负载 / 运行时间）
- 连接信息（当前 IP / 上次登录 / 失败次数）

不需要的话直接跳过即可。

## 常见问题

### 轻量服务器改不了 SSH 端口？

部分云厂商的轻量服务器 SSH 由平台代理，`sshd_config` 改端口不生效。脚本测试登录失败时会自动还原。其他安全措施（密钥登录 + 禁止 root + fail2ban）依然有效。

### fail2ban 把自己封了？

用云控制台的 VNC 登录后执行：

```bash
fail2ban-client set sshd unbanip 你的IP
```

### 重新运行脚本会冲突吗？

不会。脚本会检测已存在的用户、已配置的 BBR、已有的公钥、已存在的 Swap 等，自动跳过或提示。SSH 配置和 fail2ban 配置修改前都会创建带时间戳的备份。sysctl 参数写入时会检查去重，不会重复追加。

### Swap 应该设多大？

脚本会根据物理内存自动推荐。一般原则：**内存越小越需要 Swap**。512MB/1GB 的 VPS 不设 Swap 几乎必死（OOM Killer 会直接杀进程）。

### 内核调优参数安全吗？

这些都是常见的 Web 服务器生产环境参数，不会导致系统不稳定。如果需要还原，编辑 `/etc/sysctl.conf` 删除对应行后执行 `sysctl -p` 即可。

## 相关项目

- [ssh_hello](https://github.com/maodeyu180/ssh_hello) — SSH 登录信息美化脚本

## License

MIT
