#!/bin/bash
# =============================================================================
# VPS 初始化脚本 - 安全优先 · 多发行版兼容
# 支持: Debian/Ubuntu, CentOS/RHEL/Fedora/AlmaLinux/Rocky, Arch, Alpine, openSUSE
#
# 核心安全原则:
#   1. 永远不在验证 SSH 密钥登录成功之前禁用密码登录
#   2. 所有关键配置修改前自动备份
#   3. 高风险操作需要用户手动验证后才继续
#   4. 公钥格式校验, 防止粘贴错误
#
# 用法: 以 root 身份运行
#   chmod +x vps-init.sh && sudo bash vps-init.sh
# =============================================================================
set -euo pipefail

# ========================== Root 权限检查 (最早执行) ==========================
if [[ $EUID -ne 0 ]]; then
    echo -e "\033[0;31m[ERROR]\033[0m 此脚本必须以 root 身份运行!"
    echo ""
    echo "  请使用以下方式之一:"
    echo "    sudo bash $0"
    echo "    su -c 'bash $0'"
    echo ""
    echo "  或先切换到 root:"
    echo "    sudo -i"
    echo "    bash $0"
    exit 1
fi

# ========================== 默认配置 ==========================
DEFAULT_USER="deploy"
DEFAULT_SSH_PORT="22000"
DEFAULT_TIMEZONE="Asia/Shanghai"

# ========================== 颜色 ==========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ========================== 日志 ==========================
info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }
step()    { echo -e "\n${BOLD}${CYAN}========== $* ==========${NC}\n"; }

# ========================== 全局状态 ==========================
NEW_USER=""
NEW_SSH_PORT=""
SSH_KEY_CONFIGURED=false

# 由 detect_os 填充
OS_FAMILY=""        # debian | rhel | arch | suse | alpine
OS_ID=""            # ubuntu, debian, centos, fedora, alma, rocky, arch, alpine, opensuse-*
OS_VERSION=""       # 主版本号
SUDO_GROUP=""       # sudo | wheel
SSH_SERVICE=""      # ssh | sshd
FW_TYPE=""          # ufw | firewalld | iptables
F2B_LOGPATH=""      # fail2ban 日志路径
F2B_BACKEND=""      # fail2ban backend: auto | systemd

# ========================== 工具函数 ==========================
confirm() {
    local prompt="${1:-确认继续?}"
    local default="${2:-y}"
    local answer
    if [[ "$default" == "y" ]]; then
        read -rp "$(echo -e "${YELLOW}$prompt [Y/n]: ${NC}")" answer
        answer="${answer:-y}"
    else
        read -rp "$(echo -e "${YELLOW}$prompt [y/N]: ${NC}")" answer
        answer="${answer:-n}"
    fi
    [[ "${answer,,}" == "y" ]]
}

get_server_ip() {
    curl -s --max-time 5 ifconfig.me 2>/dev/null \
        || curl -s --max-time 5 icanhazip.com 2>/dev/null \
        || wget -qO- --timeout=5 ifconfig.me 2>/dev/null \
        || echo "无法获取"
}

validate_ssh_pubkey() {
    local key="$1"
    [[ -z "$key" ]] && return 1
    echo "$key" | grep -qE '^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+'
}

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1024 && port <= 65535 ))
}

get_current_ssh_port() {
    local port
    port=$(grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    echo "${port:-22}"
}

# ========================== 发行版检测与适配 ==========================
detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "无法检测操作系统 (/etc/os-release 不存在)"
        error "此脚本支持: Debian/Ubuntu, CentOS/RHEL/Fedora/Alma/Rocky, Arch, Alpine, openSUSE"
        exit 1
    fi

    . /etc/os-release
    OS_ID="${ID,,}"
    OS_VERSION="${VERSION_ID%%.*}"

    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop|kali|deepin)
            OS_FAMILY="debian"
            SUDO_GROUP="sudo"
            SSH_SERVICE="ssh"
            FW_TYPE="ufw"
            F2B_LOGPATH="/var/log/auth.log"
            F2B_BACKEND="auto"
            ;;
        centos|rhel|almalinux|rocky|ol|scientific)
            OS_FAMILY="rhel"
            SUDO_GROUP="wheel"
            SSH_SERVICE="sshd"
            FW_TYPE="firewalld"
            F2B_BACKEND="systemd"
            if [[ -f /var/log/secure ]]; then
                F2B_LOGPATH="/var/log/secure"
            else
                F2B_LOGPATH="%(sshd_log)s"
                F2B_BACKEND="systemd"
            fi
            ;;
        fedora)
            OS_FAMILY="rhel"
            SUDO_GROUP="wheel"
            SSH_SERVICE="sshd"
            FW_TYPE="firewalld"
            F2B_LOGPATH="%(sshd_log)s"
            F2B_BACKEND="systemd"
            ;;
        arch|manjaro|endeavouros)
            OS_FAMILY="arch"
            SUDO_GROUP="wheel"
            SSH_SERVICE="sshd"
            FW_TYPE="iptables"
            F2B_LOGPATH="%(sshd_log)s"
            F2B_BACKEND="systemd"
            ;;
        opensuse*|sles)
            OS_FAMILY="suse"
            SUDO_GROUP="wheel"
            SSH_SERVICE="sshd"
            FW_TYPE="firewalld"
            F2B_LOGPATH="/var/log/messages"
            F2B_BACKEND="auto"
            ;;
        alpine)
            OS_FAMILY="alpine"
            SUDO_GROUP="wheel"
            SSH_SERVICE="sshd"
            FW_TYPE="iptables"
            F2B_LOGPATH="/var/log/messages"
            F2B_BACKEND="auto"
            ;;
        *)
            warn "未知发行版: $OS_ID, 将尝试自动检测包管理器"
            if command -v apt &>/dev/null; then
                OS_FAMILY="debian"
            elif command -v dnf &>/dev/null; then
                OS_FAMILY="rhel"
            elif command -v yum &>/dev/null; then
                OS_FAMILY="rhel"
            elif command -v pacman &>/dev/null; then
                OS_FAMILY="arch"
            elif command -v zypper &>/dev/null; then
                OS_FAMILY="suse"
            elif command -v apk &>/dev/null; then
                OS_FAMILY="alpine"
            else
                error "无法检测包管理器, 脚本无法继续"
                exit 1
            fi
            SUDO_GROUP="wheel"
            SSH_SERVICE="sshd"
            FW_TYPE="iptables"
            F2B_LOGPATH="/var/log/auth.log"
            F2B_BACKEND="auto"
            ;;
    esac

    # Debian 系的 SSH 服务名可能是 ssh 或 sshd, 实际检测一下
    if [[ "$OS_FAMILY" == "debian" ]]; then
        if systemctl list-unit-files sshd.service &>/dev/null 2>&1; then
            SSH_SERVICE="sshd"
        fi
    fi
}

# ========================== 包管理器抽象层 ==========================
pkg_update() {
    case "$OS_FAMILY" in
        debian)  apt update -y && apt full-upgrade -y ;;
        rhel)
            if command -v dnf &>/dev/null; then
                dnf upgrade -y
            else
                yum update -y
            fi
            ;;
        arch)    pacman -Syu --noconfirm ;;
        suse)    zypper refresh && zypper update -y ;;
        alpine)  apk update && apk upgrade ;;
    esac
}

pkg_clean() {
    case "$OS_FAMILY" in
        debian)  apt autoremove -y && apt autoclean -y ;;
        rhel)
            if command -v dnf &>/dev/null; then
                dnf autoremove -y
            else
                yum autoremove -y 2>/dev/null || true
            fi
            ;;
        arch)    pacman -Sc --noconfirm 2>/dev/null || true ;;
        suse)    zypper clean ;;
        alpine)  apk cache clean 2>/dev/null || true ;;
    esac
}

pkg_install() {
    local packages=("$@")
    case "$OS_FAMILY" in
        debian)  apt install -y "${packages[@]}" ;;
        rhel)
            if command -v dnf &>/dev/null; then
                dnf install -y "${packages[@]}"
            else
                yum install -y "${packages[@]}"
            fi
            ;;
        arch)    pacman -S --noconfirm --needed "${packages[@]}" ;;
        suse)    zypper install -y "${packages[@]}" ;;
        alpine)  apk add "${packages[@]}" ;;
    esac
}

pkg_is_installed() {
    local pkg="$1"
    case "$OS_FAMILY" in
        debian)  dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" ;;
        rhel)    rpm -q "$pkg" &>/dev/null ;;
        arch)    pacman -Qi "$pkg" &>/dev/null ;;
        suse)    rpm -q "$pkg" &>/dev/null ;;
        alpine)  apk info -e "$pkg" &>/dev/null ;;
    esac
}

get_base_packages() {
    local common_all="curl wget git vim htop tree unzip"

    case "$OS_FAMILY" in
        debian)
            echo "sudo $common_all net-tools ufw fail2ban"
            ;;
        rhel)
            # EPEL is needed for fail2ban on RHEL-based
            if [[ "$OS_ID" != "fedora" ]]; then
                echo "sudo $common_all net-tools firewalld fail2ban epel-release"
            else
                echo "sudo $common_all net-tools firewalld fail2ban"
            fi
            ;;
        arch)
            echo "sudo $common_all net-tools ufw fail2ban"
            ;;
        suse)
            echo "sudo $common_all net-tools firewalld fail2ban"
            ;;
        alpine)
            echo "sudo $common_all net-tools fail2ban ip6tables"
            ;;
    esac
}

check_reboot_required() {
    if [[ "$OS_FAMILY" == "debian" ]]; then
        [[ -f /var/run/reboot-required ]]
    elif [[ "$OS_FAMILY" == "rhel" ]]; then
        if command -v needs-restarting &>/dev/null; then
            needs-restarting -r &>/dev/null
            [[ $? -eq 1 ]]
        else
            false
        fi
    else
        false
    fi
}

# ========================== 防火墙抽象层 ==========================
fw_allow_port() {
    local port="$1"
    local proto="${2:-tcp}"
    local comment="${3:-}"

    case "$FW_TYPE" in
        ufw)
            ufw allow "$port/$proto" ${comment:+comment "$comment"} 2>/dev/null \
                || ufw allow "$port/$proto"
            ;;
        firewalld)
            firewall-cmd --permanent --add-port="$port/$proto"
            ;;
        iptables)
            iptables -A INPUT -p "$proto" --dport "$port" -j ACCEPT
            if command -v ip6tables &>/dev/null; then
                ip6tables -A INPUT -p "$proto" --dport "$port" -j ACCEPT
            fi
            ;;
    esac
}

fw_set_defaults() {
    case "$FW_TYPE" in
        ufw)
            ufw default deny incoming
            ufw default allow outgoing
            ;;
        firewalld)
            firewall-cmd --set-default-zone=drop 2>/dev/null || true
            firewall-cmd --permanent --zone=drop --add-service=dhcpv6-client 2>/dev/null || true
            ;;
        iptables)
            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -P OUTPUT ACCEPT
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            if command -v ip6tables &>/dev/null; then
                ip6tables -P INPUT DROP
                ip6tables -P FORWARD DROP
                ip6tables -P OUTPUT ACCEPT
                ip6tables -A INPUT -i lo -j ACCEPT
                ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            fi
            ;;
    esac
}

fw_enable() {
    case "$FW_TYPE" in
        ufw)
            echo "y" | ufw enable
            ;;
        firewalld)
            systemctl enable --now firewalld
            firewall-cmd --reload
            ;;
        iptables)
            # 持久化 iptables 规则
            if command -v iptables-save &>/dev/null; then
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4
                if command -v ip6tables-save &>/dev/null; then
                    ip6tables-save > /etc/iptables/rules.v6
                fi
                success "iptables 规则已保存"

                if [[ "$OS_FAMILY" == "arch" ]]; then
                    systemctl enable iptables 2>/dev/null || true
                fi
            fi
            ;;
    esac
}

fw_status() {
    case "$FW_TYPE" in
        ufw)       ufw status verbose ;;
        firewalld) firewall-cmd --list-all ;;
        iptables)  iptables -L -n --line-numbers ;;
    esac
}

fw_is_active() {
    case "$FW_TYPE" in
        ufw)       ufw status 2>/dev/null | grep -q "Status: active" ;;
        firewalld) systemctl is-active firewalld &>/dev/null ;;
        iptables)  iptables -L -n 2>/dev/null | grep -qv "^$" ;;
    esac
}

# ========================== SSH 服务操作 ==========================
ssh_restart() {
    if systemctl restart "$SSH_SERVICE" 2>/dev/null; then
        return 0
    elif systemctl restart sshd 2>/dev/null; then
        return 0
    elif systemctl restart ssh 2>/dev/null; then
        return 0
    elif service sshd restart 2>/dev/null; then
        return 0
    elif rc-service sshd restart 2>/dev/null; then
        return 0
    else
        error "无法重启 SSH 服务"
        return 1
    fi
}

ssh_syntax_check() {
    sshd -t 2>/dev/null
}

# ========================== 用户创建抽象层 ==========================
create_system_user() {
    local username="$1"

    case "$OS_FAMILY" in
        debian)
            adduser --gecos "" "$username"
            ;;
        rhel|arch|suse)
            useradd -m -s /bin/bash "$username" 2>/dev/null || useradd -m "$username"
            info "请为用户 '$username' 设置密码:"
            passwd "$username"
            ;;
        alpine)
            adduser -s /bin/ash "$username"
            ;;
    esac

    usermod -aG "$SUDO_GROUP" "$username"

    # RHEL/Arch: 确保 wheel 组在 sudoers 中启用
    if [[ "$SUDO_GROUP" == "wheel" ]]; then
        local sudoers="/etc/sudoers"
        if [ -f "$sudoers" ]; then
            # 取消注释 %wheel 行
            if grep -q "^#.*%wheel.*ALL=(ALL).*ALL" "$sudoers" 2>/dev/null; then
                sed -i 's/^#\s*\(%wheel\s\+ALL=(ALL)\s\+ALL\)/\1/' "$sudoers" 2>/dev/null || true
            fi
            if grep -q "^#.*%wheel.*ALL=(ALL:ALL).*ALL" "$sudoers" 2>/dev/null; then
                sed -i 's/^#\s*\(%wheel\s\+ALL=(ALL:ALL)\s\+ALL\)/\1/' "$sudoers" 2>/dev/null || true
            fi
        fi
    fi
}

# ========================== SELinux 处理 ==========================
handle_selinux_ssh() {
    if ! command -v getenforce &>/dev/null; then
        return 0
    fi

    local se_status
    se_status=$(getenforce 2>/dev/null || echo "Disabled")

    if [[ "$se_status" == "Disabled" ]] || [[ "$se_status" == "Permissive" ]]; then
        return 0
    fi

    info "检测到 SELinux 处于 Enforcing 模式"

    # 如果端口改了, 需要告诉 SELinux
    if [[ -n "${NEW_SSH_PORT:-}" ]] && [[ "$NEW_SSH_PORT" != "22" ]]; then
        if command -v semanage &>/dev/null; then
            info "正在为 SELinux 注册 SSH 端口 $NEW_SSH_PORT..."
            semanage port -a -t ssh_port_t -p tcp "$NEW_SSH_PORT" 2>/dev/null \
                || semanage port -m -t ssh_port_t -p tcp "$NEW_SSH_PORT" 2>/dev/null \
                || warn "SELinux 端口注册失败, 可能需要手动处理"
        else
            warn "semanage 未安装, 无法自动配置 SELinux SSH 端口"
            warn "请手动安装: $(
                case $OS_FAMILY in
                    rhel) echo 'dnf install policycoreutils-python-utils' ;;
                    *)    echo 'policycoreutils-python-utils' ;;
                esac
            )"
            warn "然后执行: semanage port -a -t ssh_port_t -p tcp $NEW_SSH_PORT"
        fi
    fi

    # 修复 authorized_keys 的 SELinux 上下文
    if command -v restorecon &>/dev/null && [[ -n "${NEW_USER:-}" ]]; then
        restorecon -Rv "/home/${NEW_USER}/.ssh" 2>/dev/null || true
    fi
}

# ========================== 自动更新抽象层 ==========================
setup_auto_updates() {
    case "$OS_FAMILY" in
        debian)
            pkg_install unattended-upgrades
            echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades
            success "自动安全更新已启用 (unattended-upgrades)"
            ;;
        rhel)
            if command -v dnf &>/dev/null; then
                pkg_install dnf-automatic
                # 仅安装安全更新
                sed -i 's/^upgrade_type\s*=.*/upgrade_type = security/' /etc/dnf/automatic.conf 2>/dev/null || true
                sed -i 's/^apply_updates\s*=.*/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null || true
                systemctl enable --now dnf-automatic.timer
                success "自动安全更新已启用 (dnf-automatic)"
            else
                pkg_install yum-cron
                sed -i 's/^update_cmd\s*=.*/update_cmd = security/' /etc/yum/yum-cron.conf 2>/dev/null || true
                sed -i 's/^apply_updates\s*=.*/apply_updates = yes/' /etc/yum/yum-cron.conf 2>/dev/null || true
                systemctl enable --now yum-cron
                success "自动安全更新已启用 (yum-cron)"
            fi
            ;;
        arch)
            warn "Arch Linux 不建议自动更新 (滚动发行版, 更新可能需要手动干预)"
            info "建议定期手动执行: pacman -Syu"
            ;;
        suse)
            zypper install -y yast2-online-update-configuration 2>/dev/null || true
            info "openSUSE 请通过 YaST 配置自动更新"
            ;;
        alpine)
            info "Alpine 请通过 cron 配置 apk upgrade --available"
            ;;
    esac
}

# ========================== 阶段 0: 前置检查 ==========================
phase0_precheck() {
    step "阶段 0/7: 前置检查"

    detect_os

    info "系统信息:"
    info "  发行版:   ${PRETTY_NAME:-$OS_ID}"
    info "  OS 家族:  $OS_FAMILY"
    info "  内核:     $(uname -r)"
    info "  CPU:      $(nproc) 核 ($(lscpu 2>/dev/null | grep 'Model name' | sed 's/.*:\s*//' || echo '未知'))"
    info "  内存:     $(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || echo '未知')"
    info "  磁盘:     $(df -h / 2>/dev/null | awk 'NR==2{print $2 " (已用 " $5 ")"}' || echo '未知')"
    info "  公网 IP:  $(get_server_ip)"
    echo ""
    info "适配方案:"
    info "  包管理:   $OS_FAMILY"
    info "  防火墙:   $FW_TYPE"
    info "  SSH 服务: $SSH_SERVICE"
    info "  sudo 组:  $SUDO_GROUP"

    # SELinux 状态
    if command -v getenforce &>/dev/null; then
        local se_status
        se_status=$(getenforce 2>/dev/null || echo "未知")
        info "  SELinux:  $se_status"
        if [[ "$se_status" == "Enforcing" ]]; then
            warn "SELinux 处于强制模式, 修改 SSH 端口时需要额外配置 (脚本会自动处理)"
        fi
    fi

    echo ""
    success "前置检查通过"

    if ! confirm "以上信息是否正确? 是否继续初始化?"; then
        info "已取消"
        exit 0
    fi
}

# ========================== EOL 源修复 ==========================
# 各发行版 EOL 后官方镜像下线, 需要切换到归档源才能安装软件包
# CentOS 7/8 → vault.centos.org
# Debian ≤10  → archive.debian.org
# Ubuntu EOL  → old-releases.ubuntu.com
# Fedora EOL  → archives.fedoraproject.org

_check_url_reachable() {
    local url="$1"
    if command -v curl &>/dev/null; then
        curl -sfL --head --max-time 10 "$url" >/dev/null 2>&1
    elif command -v wget &>/dev/null; then
        wget -q --spider --timeout=10 "$url" 2>/dev/null
    else
        return 0
    fi
}

_fix_centos_eol() {
    local vault_base="http://vault.centos.org"
    local needs_fix=false

    if [[ "$OS_VERSION" == "7" || "$OS_VERSION" == "8" ]]; then
        for repo in /etc/yum.repos.d/CentOS-*.repo; do
            [[ -f "$repo" ]] || continue
            if grep -qE '^\s*mirrorlist=' "$repo" 2>/dev/null; then
                needs_fix=true
                break
            fi
        done
    else
        return 0
    fi

    $needs_fix || return 0

    warn "CentOS $OS_VERSION 已 EOL, 官方镜像已下线"
    info "将 yum 源切换到 vault.centos.org..."

    for repo in /etc/yum.repos.d/CentOS-*.repo; do
        [[ -f "$repo" ]] || continue
        cp "$repo" "${repo}.bak.$(date +%s)" 2>/dev/null || true
        sed -i 's|^\s*mirrorlist=|#mirrorlist=|g' "$repo"
        if [[ "$OS_VERSION" == "7" ]]; then
            sed -i 's|^#\s*baseurl=http://mirror.centos.org/centos|baseurl='"$vault_base"'/centos|g' "$repo"
            sed -i 's|^baseurl=http://mirror.centos.org/centos|baseurl='"$vault_base"'/centos|g' "$repo"
        else
            sed -i 's|^#\s*baseurl=http://mirror.centos.org|baseurl='"$vault_base"'/centos|g' "$repo"
            sed -i 's|^baseurl=http://mirror.centos.org|baseurl='"$vault_base"'/centos|g' "$repo"
        fi
    done

    yum clean all &>/dev/null || true
    success "yum 源已切换到 vault.centos.org"
}

_fix_debian_eol() {
    [[ "$OS_VERSION" -ge 11 ]] && return 0

    grep -q "archive.debian.org" /etc/apt/sources.list 2>/dev/null && return 0

    local codename
    codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
    [[ -z "$codename" ]] && return 0

    if _check_url_reachable "http://deb.debian.org/debian/dists/${codename}/Release"; then
        return 0
    fi

    warn "Debian $OS_VERSION ($codename) 已 EOL, 常规镜像已下线"
    info "将 apt 源切换到 archive.debian.org..."

    cp /etc/apt/sources.list "/etc/apt/sources.list.bak.$(date +%s)" 2>/dev/null || true
    sed -i -E 's|https?://[a-zA-Z0-9.\-]+/debian/?|http://archive.debian.org/debian/|g' /etc/apt/sources.list
    sed -i -E 's|https?://security\.debian\.org[^ ]*|http://archive.debian.org/debian-security/|g' /etc/apt/sources.list

    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid-until
    apt-get clean 2>/dev/null || true
    success "apt 源已切换到 archive.debian.org"
}

_fix_ubuntu_eol() {
    grep -q "old-releases.ubuntu.com" /etc/apt/sources.list 2>/dev/null && return 0

    local codename
    codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
    [[ -z "$codename" ]] && return 0

    if _check_url_reachable "http://archive.ubuntu.com/ubuntu/dists/${codename}/Release"; then
        return 0
    fi

    if ! _check_url_reachable "http://old-releases.ubuntu.com/ubuntu/dists/${codename}/Release"; then
        return 0
    fi

    warn "Ubuntu ($codename) 已 EOL, 常规镜像已下线"
    info "将 apt 源切换到 old-releases.ubuntu.com..."

    cp /etc/apt/sources.list "/etc/apt/sources.list.bak.$(date +%s)" 2>/dev/null || true
    sed -i -E 's|https?://[a-zA-Z0-9.\-]+/ubuntu/?|http://old-releases.ubuntu.com/ubuntu/|g' /etc/apt/sources.list
    sed -i -E 's|https?://security\.ubuntu\.com/ubuntu/?|http://old-releases.ubuntu.com/ubuntu/|g' /etc/apt/sources.list

    apt-get clean 2>/dev/null || true
    success "apt 源已切换到 old-releases.ubuntu.com"
}

_fix_fedora_eol() {
    local release
    release=$(rpm -E %fedora 2>/dev/null || echo "$OS_VERSION")

    if _check_url_reachable "https://mirrors.fedoraproject.org/metalink?repo=fedora-${release}&arch=$(uname -m)"; then
        return 0
    fi

    local has_metalink=false
    for repo in /etc/yum.repos.d/fedora*.repo; do
        [[ -f "$repo" ]] || continue
        if grep -qE '^\s*metalink=' "$repo" 2>/dev/null; then
            has_metalink=true
            break
        fi
    done
    $has_metalink || return 0

    warn "Fedora $release 已 EOL, 标准镜像已下线"
    info "将 dnf 源切换到 archives.fedoraproject.org..."

    for repo in /etc/yum.repos.d/fedora*.repo; do
        [[ -f "$repo" ]] || continue
        cp "$repo" "${repo}.bak.$(date +%s)" 2>/dev/null || true
        sed -i 's|^\s*metalink=|#metalink=|g' "$repo"
        sed -i 's|^#baseurl=http://download.example/pub/fedora/linux|baseurl=https://archives.fedoraproject.org/pub/archive/fedora/linux|g' "$repo"
    done

    dnf clean all &>/dev/null || true
    success "dnf 源已切换到 archives.fedoraproject.org"
}

fix_eol_repos() {
    case "$OS_ID" in
        centos)  _fix_centos_eol ;;
        debian)  _fix_debian_eol ;;
        ubuntu)  _fix_ubuntu_eol ;;
        fedora)  _fix_fedora_eol ;;
    esac
}

# ========================== 阶段 1: 系统更新与工具安装 ==========================
phase1_system_update() {
    step "阶段 1/7: 系统更新与基础工具安装"

    # --- EOL 源修复 (必须在任何包操作之前) ---
    fix_eol_repos

    # --- EPEL 源 (RHEL 家族需要) ---
    if [[ "$OS_FAMILY" == "rhel" ]] && [[ "$OS_ID" != "fedora" ]]; then
        if ! pkg_is_installed epel-release 2>/dev/null; then
            info "RHEL 系需要 EPEL 源 (提供 fail2ban 等软件)..."
            if confirm "是否安装 EPEL 源?"; then
                if command -v dnf &>/dev/null; then
                    dnf install -y epel-release
                else
                    yum install -y epel-release
                fi
                success "EPEL 源已安装"
            fi
        else
            success "EPEL 源已存在"
        fi
    fi

    # --- 系统更新 ---
    if confirm "是否更新系统软件包?"; then
        info "正在更新..."
        pkg_update

        info "正在清理..."
        pkg_clean

        if check_reboot_required; then
            warn "系统更新后需要重启才能完全生效"
            warn "建议: 完成所有配置后手动 reboot"
        else
            success "更新完成"
        fi
    else
        info "跳过系统更新"
    fi

    # --- 工具安装 ---
    echo ""
    local packages
    packages=$(get_base_packages)
    info "将安装以下软件包: $packages"

    if confirm "是否安装基础工具?"; then
        info "正在安装..."
        # shellcheck disable=SC2086
        pkg_install $packages 2>&1 || {
            warn "部分软件包安装失败, 尝试逐个安装..."
            for pkg in $packages; do
                pkg_install "$pkg" 2>/dev/null || warn "  $pkg 安装失败, 跳过"
            done
        }
        success "基础工具安装完成"
    else
        warn "跳过工具安装, 检查关键依赖..."
        for cmd in sudo curl; do
            if ! command -v "$cmd" &>/dev/null; then
                warn "$cmd 未安装, 后续功能可能受限"
            fi
        done
    fi
}

# ========================== 阶段 2: 创建非 root 用户 ==========================
phase2_create_user() {
    step "阶段 2/7: 用户配置"

    echo "创建独立用户可以避免日常操作使用 root, 提高安全性。"
    echo "如果你习惯直接用 root, 也可以跳过。"
    echo ""

    if ! confirm "是否创建新的非 root 用户?" "n"; then
        info "跳过用户创建, 将继续使用 root"
        NEW_USER=""
        return 0
    fi

    local username
    read -rp "$(echo -e "${CYAN}请输入新用户名 [默认: $DEFAULT_USER]: ${NC}")" username
    username="${username:-$DEFAULT_USER}"

    if ! echo "$username" | grep -qE '^[a-z_][a-z0-9_-]{0,31}$'; then
        error "用户名不合法 (只允许小写字母、数字、下划线、连字符, 且以字母或下划线开头)"
        return 1
    fi

    if id "$username" &>/dev/null; then
        warn "用户 '$username' 已存在"
        if confirm "是否直接使用该用户继续?"; then
            NEW_USER="$username"
            usermod -aG "$SUDO_GROUP" "$username" 2>/dev/null || true
            success "将使用已有用户: $username (已确保在 $SUDO_GROUP 组)"
            return 0
        else
            error "请重新运行脚本并选择其他用户名"
            exit 1
        fi
    fi

    info "正在创建用户 '$username'..."
    create_system_user "$username"
    success "用户 '$username' 已创建并加入 $SUDO_GROUP 组"

    NEW_USER="$username"
}

# ========================== 阶段 3: SSH 密钥配置 ==========================
phase3_ssh_key() {
    step "阶段 3/7: SSH 密钥配置 (关键安全步骤)"

    echo -e "${BOLD}此步骤将配置 SSH 密钥登录。${NC}"
    echo ""
    echo "你需要在 ${BOLD}本地电脑${NC} 上准备好 SSH 公钥。"
    echo "如果还没有, 请在本地电脑上执行:"
    echo -e "  ${CYAN}ssh-keygen -t ed25519 -C \"your@email.com\"${NC}"
    echo ""
    echo "然后查看公钥:"
    echo -e "  ${CYAN}cat ~/.ssh/id_ed25519.pub${NC}  (Linux/Mac)"
    echo -e "  ${CYAN}type %USERPROFILE%\\.ssh\\id_ed25519.pub${NC}  (Windows CMD)"
    echo -e "  ${CYAN}cat \$env:USERPROFILE\\.ssh\\id_ed25519.pub${NC}  (PowerShell)"
    echo ""

    if ! confirm "你是否已经准备好 SSH 公钥?"; then
        warn "跳过 SSH 密钥配置"
        warn "后续的 SSH 安全加固将不会禁用密码登录"
        SSH_KEY_CONFIGURED=false
        return 0
    fi

    local pubkey=""
    local attempts=0
    local max_attempts=3

    while (( attempts < max_attempts )); do
        echo ""
        echo -e "${CYAN}请粘贴你的 SSH 公钥 (以 ssh-ed25519 或 ssh-rsa 开头的完整一行):${NC}"
        read -r pubkey

        pubkey=$(echo "$pubkey" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        if validate_ssh_pubkey "$pubkey"; then
            local key_type
            key_type=$(echo "$pubkey" | awk '{print $1}')
            local key_comment
            key_comment=$(echo "$pubkey" | awk '{print $3}')
            echo ""
            success "公钥格式验证通过"
            info "  类型: $key_type"
            info "  备注: ${key_comment:-无}"
            echo ""

            if confirm "确认使用这个公钥?"; then
                break
            else
                pubkey=""
                info "请重新输入"
            fi
        else
            attempts=$((attempts + 1))
            error "公钥格式不正确! (尝试 $attempts/$max_attempts)"
            echo "公钥应该类似:"
            echo "  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host"
            echo "  ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host"
            echo ""
            if (( attempts >= max_attempts )); then
                error "多次输入失败, 跳过密钥配置"
                SSH_KEY_CONFIGURED=false
                return 0
            fi
        fi
    done

    if [[ -z "$pubkey" ]]; then
        SSH_KEY_CONFIGURED=false
        return 0
    fi

    # 安装公钥
    local target_user="${NEW_USER:-root}"
    local user_home
    user_home=$(eval echo "~${target_user}")
    local ssh_dir="$user_home/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"

    if [ -f "$auth_keys" ] && grep -qF "$pubkey" "$auth_keys" 2>/dev/null; then
        warn "该公钥已存在于 authorized_keys 中, 无需重复添加"
    else
        echo "$pubkey" >> "$auth_keys"
        success "公钥已写入 $auth_keys"
    fi

    chmod 600 "$auth_keys"
    chown -R "${target_user}:${target_user}" "$ssh_dir"

    # SELinux: 修复上下文
    if command -v restorecon &>/dev/null; then
        restorecon -Rv "$ssh_dir" 2>/dev/null || true
    fi

    # === 关键验证 ===
    echo ""
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║           请 务 必 完 成 以 下 验 证 步 骤              ║${NC}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "请 ${BOLD}新开一个终端窗口${NC}, 测试密钥登录:"
    echo ""
    local server_ip
    server_ip=$(get_server_ip)
    local current_port
    current_port=$(get_current_ssh_port)
    echo -e "  ${CYAN}ssh -p $current_port ${NEW_USER:-root}@${server_ip}${NC}"
    echo ""
    echo -e "${YELLOW}请确认: 不需要输入 服务器密码 就能登录成功${NC}"
    echo -e "${YELLOW}(如果给私钥设了 passphrase, 会提示输入私钥密码, 这是正常的)${NC}"
    echo ""

    if confirm "密钥登录测试是否成功? (一定要先测试再回答!)"; then
        SSH_KEY_CONFIGURED=true
        success "SSH 密钥验证通过, 后续将安全地禁用密码登录"
    else
        SSH_KEY_CONFIGURED=false
        warn "密钥登录未成功"
        echo ""
        echo "可能的原因:"
        echo "  1. 公钥/私钥不匹配"
        echo "  2. 文件权限不正确 (检查: ls -la $ssh_dir)"
        if command -v getenforce &>/dev/null; then
            echo "  3. SELinux 阻止访问 (检查: audit2why < /var/log/audit/audit.log)"
        fi
        echo ""
        warn "密码登录将保持开启状态以防止被锁定"
    fi
}

# ========================== 阶段 4: SSH 安全加固 ==========================
phase4_ssh_harden() {
    step "阶段 4/7: SSH 安全加固"

    local sshd_config="/etc/ssh/sshd_config"
    local sshd_backup="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"

    cp "$sshd_config" "$sshd_backup"
    success "SSH 配置已备份到: $sshd_backup"

    # --- 端口 ---
    echo ""
    local current_port
    current_port=$(get_current_ssh_port)
    info "当前 SSH 端口: $current_port"
    echo ""
    warn "注意: 部分云厂商 (阿里云/腾讯云/AWS 等) 的防火墙/安全组在控制台配置,"
    warn "系统内改端口后还需要去厂商控制台放行对应端口, 否则会连不上。"
    warn "轻量服务器的 SSH 可能由平台代理, 改端口不生效。"
    warn "如果不确定, 建议保持默认端口不变。"
    echo ""

    local new_port
    if confirm "是否修改 SSH 端口?" "n"; then
        read -rp "$(echo -e "${CYAN}请输入新的 SSH 端口 (1024-65535) [默认: $DEFAULT_SSH_PORT]: ${NC}")" new_port
        new_port="${new_port:-$DEFAULT_SSH_PORT}"
        if ! validate_port "$new_port"; then
            warn "端口不合法 (需要 1024-65535), 保持当前端口: $current_port"
            new_port="$current_port"
        fi
    else
        new_port="$current_port"
        info "保持当前端口: $new_port"
    fi
    NEW_SSH_PORT="$new_port"

    # --- 修改配置 ---
    local tmp_config
    tmp_config=$(mktemp)
    cp "$sshd_config" "$tmp_config"

    # sed 兼容: 部分系统的 sed 不支持 \s, 改用 [ \t]
    local apply_setting
    apply_setting() {
        local key="$1"
        local value="$2"
        local file="$3"
        if grep -qE "^[ \t]*#?[ \t]*${key}[ \t]+" "$file"; then
            sed -i "s/^[ \t]*#*[ \t]*${key}[ \t].*/${key} ${value}/" "$file"
        else
            echo "${key} ${value}" >> "$file"
        fi
    }

    apply_setting "Port" "$NEW_SSH_PORT" "$tmp_config"
    apply_setting "PubkeyAuthentication" "yes" "$tmp_config"
    apply_setting "MaxAuthTries" "3" "$tmp_config"
    apply_setting "ClientAliveInterval" "3600" "$tmp_config"
    apply_setting "ClientAliveCountMax" "2" "$tmp_config"
    apply_setting "PermitEmptyPasswords" "no" "$tmp_config"

    # Root 登录: 有独立用户时禁止, 否则保留
    local root_login_setting="yes"
    if [[ -n "${NEW_USER:-}" ]]; then
        root_login_setting="no"
    fi
    apply_setting "PermitRootLogin" "$root_login_setting" "$tmp_config"

    if [[ "$SSH_KEY_CONFIGURED" == true ]]; then
        apply_setting "PasswordAuthentication" "no" "$tmp_config"
        info "密码登录将被禁用 (密钥已验证通过)"
    else
        apply_setting "PasswordAuthentication" "yes" "$tmp_config"
        warn "密码登录保持开启 (密钥未验证, 防止锁定)"
    fi

    # 摘要
    echo ""
    info "SSH 配置变更摘要:"
    echo "  端口:            $(get_current_ssh_port) -> $NEW_SSH_PORT"
    if [[ -n "${NEW_USER:-}" ]]; then
        echo "  Root 登录:       -> 禁止"
    else
        echo "  Root 登录:       -> 保持允许 (未创建独立用户)"
    fi
    echo "  公钥认证:        -> 开启"
    echo "  密码登录:        -> $(if [[ "$SSH_KEY_CONFIGURED" == true ]]; then echo '禁用'; else echo '保持开启(安全起见)'; fi)"
    echo "  最大认证尝试:    -> 3 次"
    echo "  客户端超时:      -> 3600s x 2 (2小时)"
    if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]] && [[ "$NEW_SSH_PORT" != "22" ]]; then
        echo "  SELinux 端口注册: -> $NEW_SSH_PORT"
    fi
    echo ""

    if ! confirm "确认应用以上 SSH 配置?"; then
        rm -f "$tmp_config"
        warn "已跳过 SSH 配置修改"
        NEW_SSH_PORT=$(get_current_ssh_port)
        return 0
    fi

    cp "$tmp_config" "$sshd_config"
    rm -f "$tmp_config"

    # SELinux 处理 (必须在重启 SSH 之前)
    handle_selinux_ssh

    # 语法检查
    if ssh_syntax_check; then
        success "SSH 配置语法检查通过"
    else
        error "SSH 配置语法错误! 正在还原..."
        cp "$sshd_backup" "$sshd_config"
        error "已还原到备份配置"
        NEW_SSH_PORT=$(get_current_ssh_port)
        return 1
    fi

    ssh_restart

    echo ""
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║         不 要 关 闭 当 前 终 端 !!!                     ║${NC}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "请 ${BOLD}新开一个终端窗口${NC}, 测试新的 SSH 配置:"
    echo ""
    local server_ip
    server_ip=$(get_server_ip)
    echo -e "  ${CYAN}ssh -p $NEW_SSH_PORT ${NEW_USER:-root}@${server_ip}${NC}"
    if [[ "$SSH_KEY_CONFIGURED" != true ]]; then
        echo "  (需要输入用户密码)"
    fi
    echo ""

    if confirm "新终端能成功登录吗?"; then
        success "SSH 安全加固完成"
    else
        warn "登录失败! 正在还原 SSH 配置..."
        cp "$sshd_backup" "$sshd_config"
        ssh_restart
        success "已还原到备份配置并重启 SSH"
        NEW_SSH_PORT=$(get_current_ssh_port)
        echo ""
        echo "可能的原因:"
        echo "  1. 防火墙/安全组未放行新端口"
        echo "  2. 轻量服务器端口可能改不了 (平台代理 SSH)"
        if command -v getenforce &>/dev/null; then
            echo "  3. SELinux 阻止了新端口"
        fi
        echo ""
        warn "请排查后重新运行脚本, 或手动修改 /etc/ssh/sshd_config"
    fi
}

# ========================== 阶段 5: 防火墙 ==========================
phase5_firewall() {
    step "阶段 5/7: 防火墙配置 ($FW_TYPE)"

    # 检查防火墙工具是否可用, 不可用时尝试切换
    case "$FW_TYPE" in
        ufw)
            if ! command -v ufw &>/dev/null; then
                if command -v firewall-cmd &>/dev/null; then
                    FW_TYPE="firewalld"
                    warn "ufw 不可用, 切换到 firewalld"
                else
                    FW_TYPE="iptables"
                    warn "ufw 不可用, 切换到 iptables"
                fi
            fi
            ;;
        firewalld)
            if ! command -v firewall-cmd &>/dev/null; then
                if command -v ufw &>/dev/null; then
                    FW_TYPE="ufw"
                    warn "firewalld 不可用, 切换到 ufw"
                else
                    FW_TYPE="iptables"
                    warn "firewalld 不可用, 切换到 iptables"
                fi
            fi
            ;;
    esac

    info "使用防火墙: $FW_TYPE"

    if ! confirm "是否配置防火墙?"; then
        info "跳过防火墙配置"
        return 0
    fi

    info "设置默认策略: 拒绝入站, 允许出站"
    fw_set_defaults

    # SSH
    info "放行 SSH 端口: $NEW_SSH_PORT/tcp"
    fw_allow_port "$NEW_SSH_PORT" "tcp" "SSH"

    if [[ "$NEW_SSH_PORT" != "22" ]]; then
        if confirm "是否同时放行 22 端口? (推荐: 轻量服务器端口可能改不了)"; then
            fw_allow_port "22" "tcp" "SSH-fallback"
        fi
    fi

    # HTTP/HTTPS
    if confirm "是否放行 HTTP (80) 和 HTTPS (443) 端口?"; then
        fw_allow_port "80" "tcp" "HTTP"
        fw_allow_port "443" "tcp" "HTTPS"
    fi

    # 自定义端口
    while confirm "是否需要放行其他端口?" "n"; do
        local extra_port
        read -rp "$(echo -e "${CYAN}请输入端口号: ${NC}")" extra_port
        if [[ "$extra_port" =~ ^[0-9]+$ ]] && (( extra_port >= 1 && extra_port <= 65535 )); then
            local proto
            read -rp "$(echo -e "${CYAN}协议 [tcp/udp/both, 默认 tcp]: ${NC}")" proto
            proto="${proto:-tcp}"
            if [[ "$proto" == "both" ]]; then
                fw_allow_port "$extra_port" "tcp"
                fw_allow_port "$extra_port" "udp"
            else
                fw_allow_port "$extra_port" "$proto"
            fi
            success "已放行 $extra_port/$proto"
        else
            warn "端口号不合法, 跳过"
        fi
    done

    echo ""
    warn "启用防火墙可能会中断现有连接 (SSH 端口已放行则不会)"
    if confirm "确认启用防火墙?"; then
        fw_enable
        echo ""
        fw_status
        echo ""
        success "防火墙已启用"
    else
        warn "跳过防火墙启用"
    fi
}

# ========================== 阶段 6: 系统优化与安全加固 ==========================
phase6_extras() {
    step "阶段 6/7: 系统优化与安全加固"

    # ======================================================================
    #  6.1 主机名
    # ======================================================================
    echo -e "\n${BOLD}[6.1 主机名]${NC}"
    local current_hostname
    current_hostname=$(hostname)
    info "当前主机名: $current_hostname"

    if confirm "是否修改主机名? (多台服务器时方便区分)"; then
        local new_hostname
        read -rp "$(echo -e "${CYAN}请输入新主机名 [如 my-vps, prod-web-01]: ${NC}")" new_hostname
        if [[ -n "$new_hostname" ]]; then
            # 合法性: 字母数字和连字符, 不超过63字符
            if echo "$new_hostname" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'; then
                if command -v hostnamectl &>/dev/null; then
                    hostnamectl set-hostname "$new_hostname"
                else
                    echo "$new_hostname" > /etc/hostname
                    hostname "$new_hostname" 2>/dev/null || true
                fi
                # 更新 /etc/hosts 避免 sudo 报警
                if ! grep -q "$new_hostname" /etc/hosts 2>/dev/null; then
                    sed -i "s/^127\.0\.0\.1\s.*/& $new_hostname/" /etc/hosts 2>/dev/null \
                        || echo "127.0.0.1 $new_hostname" >> /etc/hosts
                fi
                success "主机名已设置为: $new_hostname"
            else
                warn "主机名格式不合法 (只允许字母/数字/连字符, 不超过63字符)"
            fi
        fi
    fi

    # ======================================================================
    #  6.2 Swap 虚拟内存
    # ======================================================================
    echo -e "\n${BOLD}[6.2 Swap 虚拟内存]${NC}"
    local current_swap
    current_swap=$(free -m | awk '/^Swap:/{print $2}')
    local total_mem
    total_mem=$(free -m | awk '/^Mem:/{print $2}')

    if (( current_swap > 0 )); then
        local swap_used
        swap_used=$(free -m | awk '/^Swap:/{print $3}')
        success "Swap 已存在: ${current_swap}MB (已用 ${swap_used}MB)"
        if ! confirm "是否重新配置 Swap?" "n"; then
            info "保持现有 Swap"
        else
            _configure_swap "$total_mem"
        fi
    else
        warn "当前没有 Swap!"
        info "物理内存: ${total_mem}MB"
        if (( total_mem <= 2048 )); then
            warn "内存 <= 2GB, 强烈建议配置 Swap, 否则内存耗尽时进程会被直接杀掉"
        fi
        if confirm "是否配置 Swap?"; then
            _configure_swap "$total_mem"
        fi
    fi

    # ======================================================================
    #  6.3 系统语言环境 (Locale)
    # ======================================================================
    echo -e "\n${BOLD}[6.3 系统语言环境 (Locale)]${NC}"
    local current_lang
    current_lang=$(locale 2>/dev/null | grep "^LANG=" | cut -d= -f2 || echo "未设置")
    info "当前 LANG: $current_lang"

    if [[ "$current_lang" != *"UTF-8"* ]] && [[ "$current_lang" != *"utf8"* ]]; then
        warn "当前未使用 UTF-8, 部分工具可能出现乱码"
        if confirm "是否设置为 en_US.UTF-8?"; then
            _configure_locale
        fi
    else
        success "Locale 已是 UTF-8"
    fi

    # ======================================================================
    #  6.4 BBR 加速 + 内核网络调优
    # ======================================================================
    echo -e "\n${BOLD}[6.4 BBR 加速 + 内核网络调优]${NC}"
    local current_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")

    if [[ "$current_cc" == "bbr" ]]; then
        success "BBR 已经开启"
    else
        info "当前拥塞控制算法: $current_cc"
        if confirm "是否开启 BBR 加速?"; then
            _sysctl_set "net.core.default_qdisc" "fq"
            _sysctl_set "net.ipv4.tcp_congestion_control" "bbr"
            sysctl -p > /dev/null 2>&1

            local new_cc
            new_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
            if [[ "$new_cc" == "bbr" ]]; then
                success "BBR 已成功开启"
            else
                warn "BBR 开启可能需要重启后生效"
                warn "当前内核 $(uname -r) 可能不支持 BBR (需要 4.9+)"
            fi
        fi
    fi

    if confirm "是否应用内核网络调优参数? (优化 Web 服务器性能)" "n"; then
        _configure_kernel_network
    fi

    # ======================================================================
    #  6.5 fail2ban 防暴力破解
    # ======================================================================
    echo -e "\n${BOLD}[6.5 fail2ban 防暴力破解]${NC}"
    if ! command -v fail2ban-client &>/dev/null; then
        warn "fail2ban 未安装, 跳过配置"
    elif confirm "是否配置 fail2ban?"; then
        local jail_local="/etc/fail2ban/jail.local"

        if [ -f "$jail_local" ]; then
            cp "$jail_local" "$jail_local.bak.$(date +%Y%m%d%H%M%S)"
            info "已备份原配置"
        fi

        local f2b_maxretry f2b_bantime f2b_findtime
        read -rp "$(echo -e "${CYAN}最大尝试次数 [默认: 3]: ${NC}")" f2b_maxretry
        f2b_maxretry="${f2b_maxretry:-3}"
        read -rp "$(echo -e "${CYAN}封禁时间(秒) [默认: 3600 即1小时]: ${NC}")" f2b_bantime
        f2b_bantime="${f2b_bantime:-3600}"
        read -rp "$(echo -e "${CYAN}检测窗口(秒) [默认: 600 即10分钟]: ${NC}")" f2b_findtime
        f2b_findtime="${f2b_findtime:-600}"

        cat > "$jail_local" <<JAILEOF
[DEFAULT]
bantime  = $f2b_bantime
findtime = $f2b_findtime
maxretry = $f2b_maxretry

[sshd]
enabled  = true
port     = $NEW_SSH_PORT
filter   = sshd
backend  = $F2B_BACKEND
logpath  = $F2B_LOGPATH
maxretry = $f2b_maxretry
bantime  = $f2b_bantime
findtime = $f2b_findtime
JAILEOF

        systemctl restart fail2ban 2>/dev/null || service fail2ban restart 2>/dev/null || rc-service fail2ban restart 2>/dev/null
        systemctl enable fail2ban 2>/dev/null || true
        success "fail2ban 已配置并启动"
        fail2ban-client status sshd 2>/dev/null || true
    fi

    # ======================================================================
    #  6.6 系统时区
    # ======================================================================
    echo -e "\n${BOLD}[6.6 系统时区]${NC}"
    local current_tz
    current_tz=$(timedatectl show -p Timezone --value 2>/dev/null \
        || cat /etc/timezone 2>/dev/null \
        || echo "unknown")
    info "当前时区: $current_tz"

    if confirm "是否修改时区?"; then
        local tz
        read -rp "$(echo -e "${CYAN}请输入时区 [默认: $DEFAULT_TIMEZONE]: ${NC}")" tz
        tz="${tz:-$DEFAULT_TIMEZONE}"

        if command -v timedatectl &>/dev/null; then
            if timedatectl set-timezone "$tz" 2>/dev/null; then
                success "时区已设置为: $tz ($(date))"
            else
                warn "时区设置失败, 请检查名称"
                echo "  常用: Asia/Shanghai, Asia/Tokyo, America/New_York, Europe/London"
            fi
        elif [ -f "/usr/share/zoneinfo/$tz" ]; then
            ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime
            echo "$tz" > /etc/timezone 2>/dev/null || true
            success "时区已设置为: $tz ($(date))"
        else
            warn "时区 '$tz' 不存在"
        fi
    fi

    # ======================================================================
    #  6.7 命令历史增强
    # ======================================================================
    echo -e "\n${BOLD}[6.7 命令历史增强 (安全审计)]${NC}"
    echo "  增强后效果:"
    echo "    - 每条命令记录执行时间"
    echo "    - 历史记录保留 10000 条"
    echo "    - 多终端不会互相覆盖历史"

    if confirm "是否增强命令历史记录?"; then
        _configure_bash_history
    fi

    # ======================================================================
    #  6.8 自动安全更新
    # ======================================================================
    echo -e "\n${BOLD}[6.8 自动安全更新]${NC}"
    if confirm "是否启用自动安全更新?" "n"; then
        setup_auto_updates
    fi
}

# ---- Swap 配置实现 ----
_configure_swap() {
    local total_mem="$1"
    local recommended_swap

    # 推荐大小: <=1GB内存给2倍, 1-4GB给等量, >4GB给一半(但至少2G)
    if (( total_mem <= 1024 )); then
        recommended_swap=$(( total_mem * 2 ))
    elif (( total_mem <= 4096 )); then
        recommended_swap=$total_mem
    else
        recommended_swap=$(( total_mem / 2 ))
        (( recommended_swap < 2048 )) && recommended_swap=2048
    fi

    local swap_size
    read -rp "$(echo -e "${CYAN}Swap 大小(MB) [默认: ${recommended_swap}MB, 推荐物理内存 ${total_mem}MB 的 $(( recommended_swap * 100 / total_mem ))%]: ${NC}")" swap_size
    swap_size="${swap_size:-$recommended_swap}"

    if ! [[ "$swap_size" =~ ^[0-9]+$ ]] || (( swap_size < 256 )); then
        warn "Swap 大小不合法 (最小 256MB), 跳过"
        return 0
    fi

    local swapfile="/swapfile"

    # 如果已有 swap, 先关闭
    if swapon --show 2>/dev/null | grep -q "$swapfile"; then
        info "关闭旧的 $swapfile..."
        swapoff "$swapfile" 2>/dev/null || true
        rm -f "$swapfile"
    fi

    # 检查磁盘空间
    local free_disk
    free_disk=$(df -m / | awk 'NR==2{print $4}')
    if (( swap_size > free_disk - 1024 )); then
        error "磁盘剩余空间不足 (剩余 ${free_disk}MB, 需要至少 $(( swap_size + 1024 ))MB)"
        return 0
    fi

    info "正在创建 ${swap_size}MB Swap 文件..."

    # dd 方式 (兼容性最好, fallocate 在某些文件系统上不支持 swap)
    dd if=/dev/zero of="$swapfile" bs=1M count="$swap_size" status=progress 2>&1

    chmod 600 "$swapfile"
    mkswap "$swapfile" > /dev/null
    swapon "$swapfile"

    # 持久化到 fstab
    if ! grep -q "$swapfile" /etc/fstab 2>/dev/null; then
        echo "$swapfile none swap sw 0 0" >> /etc/fstab
    fi

    # swappiness: 低值=尽量用物理内存, 高值=积极用swap
    local swappiness=10
    _sysctl_set "vm.swappiness" "$swappiness"
    # 减少 inode/dentry 缓存回收压力
    _sysctl_set "vm.vfs_cache_pressure" "50"
    sysctl -p > /dev/null 2>&1

    success "Swap 配置完成: ${swap_size}MB (swappiness=$swappiness)"
    free -h | grep -i swap
}

# ---- Locale 配置实现 ----
_configure_locale() {
    local target_locale="en_US.UTF-8"

    case "$OS_FAMILY" in
        debian)
            # 生成 locale
            if command -v locale-gen &>/dev/null; then
                sed -i "s/^# *${target_locale}/${target_locale}/" /etc/locale.gen 2>/dev/null || true
                echo "$target_locale UTF-8" >> /etc/locale.gen 2>/dev/null
                locale-gen "$target_locale" 2>/dev/null || locale-gen 2>/dev/null
            fi
            update-locale LANG="$target_locale" 2>/dev/null || true
            ;;
        rhel|suse)
            if command -v localectl &>/dev/null; then
                # RHEL 8+/Fedora: langpacks
                pkg_install glibc-langpack-en 2>/dev/null || pkg_install glibc-locale-source 2>/dev/null || true
                localectl set-locale LANG="$target_locale"
            fi
            ;;
        arch)
            sed -i "s/^#${target_locale}/${target_locale}/" /etc/locale.gen 2>/dev/null || true
            locale-gen 2>/dev/null
            echo "LANG=$target_locale" > /etc/locale.conf
            ;;
        alpine)
            # Alpine 使用 musl, locale 支持有限
            echo "export LANG=$target_locale" > /etc/profile.d/locale.sh
            echo "export LC_ALL=$target_locale" >> /etc/profile.d/locale.sh
            chmod +x /etc/profile.d/locale.sh
            ;;
    esac

    # 通用: 写入 /etc/environment 作为兜底
    if ! grep -q "^LANG=" /etc/environment 2>/dev/null; then
        echo "LANG=$target_locale" >> /etc/environment
    fi

    export LANG="$target_locale"
    success "Locale 已设置为: $target_locale"
}

# ---- 内核网络调优实现 ----
_configure_kernel_network() {
    info "应用内核网络调优参数..."

    # TCP 连接队列 (防止高并发时连接被丢弃)
    _sysctl_set "net.core.somaxconn" "65535"
    _sysctl_set "net.core.netdev_max_backlog" "65535"
    _sysctl_set "net.ipv4.tcp_max_syn_backlog" "65535"

    # TCP 快速回收与复用 (减少 TIME_WAIT 堆积)
    _sysctl_set "net.ipv4.tcp_tw_reuse" "1"
    _sysctl_set "net.ipv4.tcp_fin_timeout" "15"

    # TCP keepalive (更快发现断连)
    _sysctl_set "net.ipv4.tcp_keepalive_time" "600"
    _sysctl_set "net.ipv4.tcp_keepalive_intvl" "30"
    _sysctl_set "net.ipv4.tcp_keepalive_probes" "5"

    # 文件描述符上限
    _sysctl_set "fs.file-max" "1048576"

    # TCP 内存与窗口 (提升吞吐)
    _sysctl_set "net.core.rmem_max" "16777216"
    _sysctl_set "net.core.wmem_max" "16777216"
    _sysctl_set "net.ipv4.tcp_rmem" "4096 212992 16777216"
    _sysctl_set "net.ipv4.tcp_wmem" "4096 212992 16777216"

    # 开启 TCP Fast Open
    _sysctl_set "net.ipv4.tcp_fastopen" "3"

    # 本地端口范围 (防止高并发时端口耗尽)
    _sysctl_set "net.ipv4.ip_local_port_range" "1024 65535"

    sysctl -p > /dev/null 2>&1
    success "内核网络调优完成"

    echo "  主要调整:"
    echo "    - TCP 连接队列:    65535"
    echo "    - TIME_WAIT 复用:  开启"
    echo "    - TCP Fast Open:   开启"
    echo "    - 文件描述符上限:  1048576"
    echo "    - 本地端口范围:    1024-65535"
}

# ---- sysctl 写入工具 (避免重复追加) ----
_sysctl_set() {
    local key="$1"
    local value="$2"
    local conf="/etc/sysctl.conf"

    if grep -qE "^${key}\s*=" "$conf" 2>/dev/null; then
        sed -i "s|^${key}\s*=.*|${key} = ${value}|" "$conf"
    elif grep -qE "^#\s*${key}\s*=" "$conf" 2>/dev/null; then
        sed -i "s|^#\s*${key}\s*=.*|${key} = ${value}|" "$conf"
    else
        echo "${key} = ${value}" >> "$conf"
    fi
}

# ---- Bash 历史记录增强实现 ----
_configure_bash_history() {
    local history_conf="/etc/profile.d/history-enhance.sh"

    cat > "$history_conf" <<'HISTEOF'
# Command history enhancement - added by vps-init
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTCONTROL=ignoredups:ignorespace
shopt -s histappend 2>/dev/null
export PROMPT_COMMAND="history -a; ${PROMPT_COMMAND:-}"
HISTEOF

    chmod 644 "$history_conf"
    success "命令历史增强已配置"
    info "  时间戳格式: 2026-03-19 14:30:00"
    info "  保留条数:   10000 (文件 20000)"
    info "  去重:       相邻重复命令自动去重"
    info "  多终端:     每次命令后立即追加, 不互相覆盖"
    info "  生效方式:   重新登录或 source $history_conf"
}

# ========================== 阶段 7: 总结 ==========================
phase7_summary() {
    step "阶段 7/7: 初始化总结与验证"

    local server_ip
    server_ip=$(get_server_ip)
    local checks_passed=0
    local checks_total=0

    echo -e "${BOLD}===== 系统检查清单 =====${NC}"
    echo ""

    _check_item() {
        local status="$1" label="$2"
        checks_total=$((checks_total + 1))
        if [[ "$status" == "ok" ]]; then
            echo -e "  ${GREEN}✓${NC} $label"
            checks_passed=$((checks_passed + 1))
        elif [[ "$status" == "warn" ]]; then
            echo -e "  ${YELLOW}△${NC} $label"
        else
            echo -e "  ${RED}✗${NC} $label"
        fi
    }

    # 1. 主机名
    local cur_hostname
    cur_hostname=$(hostname)
    _check_item "ok" "主机名: $cur_hostname"

    # 2. 非 root 用户
    if [[ -n "${NEW_USER:-}" ]] && id "${NEW_USER}" &>/dev/null; then
        _check_item "ok" "用户 '${NEW_USER}' (${SUDO_GROUP} 组)"
    elif [[ -z "${NEW_USER:-}" ]]; then
        _check_item "warn" "使用 root 登录 (未创建独立用户)"
    else
        _check_item "fail" "未创建非 root 用户"
    fi

    # 3. SSH 密钥
    local user_home
    user_home=$(eval echo "~${NEW_USER:-root}")
    local auth_file="$user_home/.ssh/authorized_keys"
    if [ -f "$auth_file" ] && [ -s "$auth_file" ]; then
        _check_item "ok" "SSH 公钥已配置"
    else
        _check_item "fail" "SSH 公钥未配置"
    fi

    # 4. 密码登录状态
    local pass_auth
    pass_auth=$(grep -E '^[ \t]*PasswordAuthentication[ \t]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -1)
    if [[ "$pass_auth" == "no" ]]; then
        _check_item "ok" "密码登录已禁用"
    else
        _check_item "warn" "密码登录仍开启$(if [[ "$SSH_KEY_CONFIGURED" != true ]]; then echo ' (密钥未验证, 安全保留)'; fi)"
    fi

    # 5. Root 登录
    local root_login
    root_login=$(grep -E '^[ \t]*PermitRootLogin[ \t]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -1)
    if [[ "$root_login" == "no" ]]; then
        _check_item "ok" "Root SSH 已禁止"
    else
        _check_item "warn" "Root SSH 仍然允许"
    fi

    # 6. SSH 端口
    local ssh_port
    ssh_port=$(get_current_ssh_port)
    _check_item "ok" "SSH 端口: $ssh_port"

    # 7. Swap
    local swap_total
    swap_total=$(free -m | awk '/^Swap:/{print $2}')
    if (( swap_total > 0 )); then
        _check_item "ok" "Swap: ${swap_total}MB"
    else
        _check_item "warn" "Swap 未配置"
    fi

    # 8. 防火墙
    if fw_is_active; then
        _check_item "ok" "防火墙已启用 ($FW_TYPE)"
    else
        _check_item "warn" "防火墙未启用"
    fi

    # 9. BBR
    local bbr_status
    bbr_status=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    if [[ "$bbr_status" == "bbr" ]]; then
        _check_item "ok" "BBR 加速已开启"
    else
        _check_item "warn" "BBR 未开启 (当前: $bbr_status)"
    fi

    # 10. fail2ban
    if systemctl is-active fail2ban &>/dev/null || service fail2ban status &>/dev/null 2>&1; then
        _check_item "ok" "fail2ban 运行中"
    else
        _check_item "warn" "fail2ban 未运行"
    fi

    # 11. 时区
    local tz
    tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "unknown")
    _check_item "ok" "时区: $tz"

    # 12. Locale
    local cur_lang
    cur_lang=$(echo "${LANG:-$(locale 2>/dev/null | grep ^LANG= | cut -d= -f2)}")
    if [[ "$cur_lang" == *"UTF-8"* ]] || [[ "$cur_lang" == *"utf8"* ]]; then
        _check_item "ok" "Locale: $cur_lang"
    else
        _check_item "warn" "Locale: ${cur_lang:-未设置} (非 UTF-8)"
    fi

    # 13. 命令历史
    if [ -f /etc/profile.d/history-enhance.sh ]; then
        _check_item "ok" "命令历史增强已配置"
    else
        _check_item "warn" "命令历史增强未配置"
    fi

    echo ""
    echo -e "${BOLD}得分: ${checks_passed}/${checks_total}${NC}"

    # 连接信息
    echo ""
    echo -e "${BOLD}===== 连接信息 =====${NC}"
    echo ""
    echo "  服务器 IP:  $server_ip"
    echo "  SSH 端口:   $ssh_port"
    echo "  登录用户:   ${NEW_USER:-root}"
    echo "  系统:       ${PRETTY_NAME:-$OS_ID} ($OS_FAMILY)"
    echo ""
    echo "  登录命令:"
    echo -e "    ${CYAN}ssh -p $ssh_port ${NEW_USER:-root}@${server_ip}${NC}"

    echo ""
    echo -e "${BOLD}===== 本地 SSH Config 建议 =====${NC}"
    echo ""
    echo -e "  ${CYAN}Host my-vps${NC}"
    echo -e "  ${CYAN}    HostName ${server_ip}${NC}"
    echo -e "  ${CYAN}    User ${NEW_USER:-root}${NC}"
    echo -e "  ${CYAN}    Port ${ssh_port}${NC}"
    echo -e "  ${CYAN}    IdentityFile ~/.ssh/id_ed25519${NC}"

    echo ""
    echo -e "${BOLD}===== 关键文件 =====${NC}"
    echo ""
    echo "  SSH 配置:       /etc/ssh/sshd_config"
    echo "  SSH 备份:       /etc/ssh/sshd_config.bak.*"
    echo "  授权密钥:       $user_home/.ssh/authorized_keys"
    echo "  fail2ban:       /etc/fail2ban/jail.local"

    if check_reboot_required; then
        echo ""
        warn "系统内核已更新, 建议执行 reboot 重启服务器"
    fi

    echo ""
    success "VPS 初始化完成!"
}

# ========================== 附加: SSH Hello 美化 ==========================
phase_bonus_ssh_hello() {
    echo ""
    echo -e "${BOLD}${CYAN}========== 附加: SSH 登录信息美化 ==========${NC}"
    echo ""
    echo "安装 ssh_hello 后, 每次 SSH 登录会自动显示:"
    echo "  - 服务器状态 (CPU/内存/磁盘/负载)"
    echo "  - 连接信息 (IP/登录时间/失败次数)"
    echo "  - 自定义 ASCII 艺术字 Banner"
    echo ""
    echo -e "项目地址: ${CYAN}https://github.com/maodeyu180/ssh_hello${NC}"
    echo ""

    if ! confirm "是否安装 SSH 登录信息美化脚本?"; then
        info "跳过 ssh_hello 安装"
        return 0
    fi

    info "正在下载 ssh_hello..."
    local tmp_script
    tmp_script=$(mktemp)

    # 优先使用国内镜像
    if curl -o "$tmp_script" -sSL --max-time 10 \
        "https://ghfast.top/https://raw.githubusercontent.com/maodeyu180/ssh_hello/main/ssh_info.sh" 2>/dev/null; then
        success "下载完成 (国内镜像)"
    elif curl -o "$tmp_script" -sSL --max-time 15 \
        "https://raw.githubusercontent.com/maodeyu180/ssh_hello/main/ssh_info.sh" 2>/dev/null; then
        success "下载完成 (GitHub)"
    elif wget -qO "$tmp_script" --timeout=15 \
        "https://raw.githubusercontent.com/maodeyu180/ssh_hello/main/ssh_info.sh" 2>/dev/null; then
        success "下载完成 (wget)"
    else
        error "下载失败, 请稍后手动安装"
        echo -e "  手动安装命令:"
        echo -e "  ${CYAN}curl -o ssh_info.sh -sSL https://raw.githubusercontent.com/maodeyu180/ssh_hello/main/ssh_info.sh && bash ssh_info.sh${NC}"
        rm -f "$tmp_script"
        return 0
    fi

    if [ ! -s "$tmp_script" ]; then
        error "下载文件为空, 跳过"
        rm -f "$tmp_script"
        return 0
    fi

    info "启动 ssh_hello 安装向导 (按提示输入自定义文本和颜色)..."
    echo ""
    bash "$tmp_script"
    rm -f "$tmp_script"

    echo ""
    success "ssh_hello 安装完成! 重新 SSH 连接即可看到效果"
}

# ========================== 主流程 ==========================
main() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║   VPS 安全初始化脚本 - 多发行版兼容 · 安全优先  ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "  支持: Debian/Ubuntu, CentOS/RHEL/Fedora/Alma/Rocky,"
    echo "        Arch, Alpine, openSUSE"
    echo ""
    echo "  执行步骤:"
    echo "    1. 系统更新与工具安装"
    echo "    2. 用户配置 (可选创建非 root 用户)"
    echo "    3. SSH 密钥配置 (含验证)"
    echo "    4. SSH 安全加固 (含回滚)"
    echo "    5. 防火墙配置 (ufw/firewalld/iptables 自动选择)"
    echo "    6. 系统优化 (主机名/Swap/Locale/BBR/内核调优/"
    echo "                  fail2ban/时区/命令历史/自动更新)"
    echo "    7. 总结与验证清单"
    echo ""
    echo -e "  ${YELLOW}每个关键步骤都会要求确认, 可随时跳过${NC}"
    echo ""

    if ! confirm "是否开始?"; then
        info "已取消"
        exit 0
    fi

    phase0_precheck
    phase1_system_update
    phase2_create_user
    phase3_ssh_key
    phase4_ssh_harden
    phase5_firewall
    phase6_extras
    phase_bonus_ssh_hello
    phase7_summary
}

main "$@"
