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
#   chmod +x vps-init.sh
#   bash vps-init.sh            # 已经是 root
#   sudo bash vps-init.sh       # 普通用户通过 sudo 提权
# =============================================================================
# source 时只加载函数, 供隔离测试使用; 权限/平台检查在 main 中执行。

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
SUDO_VERIFIED=false
SSHD_CONFIG="/etc/ssh/sshd_config"
ROLLBACK_DIR=""
ROLLBACK_SECONDS=180
FW_ZONES=()

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
        read -rp "$(echo -e "${YELLOW}$prompt [Y/n]: ${NC}")" answer || return 1
        answer="${answer:-y}"
    else
        read -rp "$(echo -e "${YELLOW}$prompt [y/N]: ${NC}")" answer || return 1
        answer="${answer:-n}"
    fi
    [[ "${answer,,}" == "y" ]]
}

get_server_ip() {
    local _client_ip _client_port server_ip server_port
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        read -r _client_ip _client_port server_ip server_port <<< "$SSH_CONNECTION"
        printf '%s\n' "$server_ip"
        return
    fi
    curl -fsS --max-time 5 https://ifconfig.me/ip 2>/dev/null \
        || curl -fsS --max-time 5 https://icanhazip.com 2>/dev/null \
        || wget -qO- --timeout=5 https://ifconfig.me/ip 2>/dev/null \
        || echo "无法获取"
}

validate_ssh_pubkey() {
    local key="$1"
    [[ -n "$key" && "$key" != *$'\n'* && "$key" != *$'\r'* ]] || return 1
    [[ "$key" =~ ^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)[[:blank:]] ]] || return 1
    command -v ssh-keygen &>/dev/null || return 1
    # 交给 OpenSSH 解码实际密钥, 不能只验证 base64 字符的外观。
    ssh-keygen -lf /dev/stdin <<< "$key" >/dev/null 2>&1
}

validate_port() {
    local port="$1"
    local minimum="${2:-1024}"
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= minimum && 10#$port <= 65535 ))
}

ssh_effective_config() {
    local user="${1:-${NEW_USER:-root}}" config="${2:-$SSHD_CONFIG}"
    local connection="${SSH_CONNECTION:-}"
    local addr _client_port local_addr local_port
    read -r addr _client_port local_addr local_port <<< "$connection"
    local_port="${3:-${local_port:-22}}"
    sshd -T -f "$config" -C "user=$user,host=${addr:-localhost},addr=${addr:-127.0.0.1},laddr=${local_addr:-127.0.0.1},lport=$local_port"
}

get_configured_ssh_ports() {
    ssh_effective_config | awk '$1 == "port" && !seen[$2]++ {print $2}'
}

get_current_ssh_port() {
    local _client_ip _client_port server_ip server_port
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        read -r _client_ip _client_port server_ip server_port <<< "$SSH_CONNECTION"
        if validate_port "$server_port" 1; then
            printf '%s\n' "$server_port"
            return
        fi
    fi
    get_configured_ssh_ports | awk 'NR == 1 {print}'
}

get_user_home() {
    getent passwd "$1" | awk -F: '$6 ~ /^\// {print $6}'
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
    OS_VERSION="${VERSION_ID:-}"
    OS_VERSION="${OS_VERSION%%.*}"

    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop|kali|deepin)
            OS_FAMILY="debian"
            SUDO_GROUP="sudo"
            SSH_SERVICE="ssh"
            FW_TYPE="ufw"
            # Debian 12 / Ubuntu 24.04+ 默认不再生成 /var/log/auth.log
            # (rsyslog 不再默认安装, 日志只写入 systemd journal)
            if [[ -f /var/log/auth.log ]]; then
                F2B_LOGPATH="/var/log/auth.log"
                F2B_BACKEND="auto"
            else
                F2B_LOGPATH=""
                F2B_BACKEND="systemd"
            fi
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
            FW_TYPE="ufw"
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
        if [[ "$(systemctl show -p LoadState --value ssh.service 2>/dev/null)" != "loaded" ]] &&
           [[ "$(systemctl show -p LoadState --value sshd.service 2>/dev/null)" == "loaded" ]]; then
            SSH_SERVICE="sshd"
        fi
    fi
}

# ========================== 包管理器抽象层 ==========================
pkg_update() {
    case "$OS_FAMILY" in
        debian)  apt-get update && apt-get upgrade -y ;;
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
        debian)  apt-get autoclean -y ;;
        rhel)
            if command -v dnf &>/dev/null; then
                dnf clean packages
            else
                yum clean packages
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
        debian)  apt-get install -y "${packages[@]}" ;;
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
                echo "sudo $common_all net-tools firewalld fail2ban"
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
            echo "sudo $common_all net-tools fail2ban iptables ip6tables iproute2 util-linux tzdata"
            ;;
    esac
}

check_reboot_required() {
    if [[ "$OS_FAMILY" == "debian" ]]; then
        [[ -f /var/run/reboot-required ]]
    elif [[ "$OS_FAMILY" == "rhel" ]]; then
        if command -v needs-restarting &>/dev/null; then
            local result=0
            needs-restarting -r &>/dev/null || result=$?
            [[ "$result" -eq 1 ]]
        else
            false
        fi
    else
        false
    fi
}

# ========================== 防火墙抽象层 ==========================
fw_is_active() {
    case "$FW_TYPE" in
        ufw) LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active' ;;
        firewalld) firewall-cmd --state &>/dev/null ;;
        iptables) iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP$' ;;
        *) return 1 ;;
    esac
}

fw_prepare_zones() {
    FW_ZONES=()
    local zone zones default_zone
    if firewall-cmd --state &>/dev/null; then
        default_zone=$(firewall-cmd --get-default-zone) || return 1
        zones=$(firewall-cmd --get-active-zones) || return 1
        zones=$(awk '/^[^[:space:]]/ {print $1}' <<< "$zones")
    else
        default_zone=$(firewall-offline-cmd --get-default-zone) || return 1
        # 停用的 firewalld 也可能已有接口/source 绑定, 不能只放行默认 zone。
        zones=""
        local all_zones interfaces sources
        all_zones=$(firewall-offline-cmd --get-zones) || return 1
        for zone in $all_zones; do
            interfaces=$(firewall-offline-cmd --zone="$zone" --list-interfaces) || return 1
            sources=$(firewall-offline-cmd --zone="$zone" --list-sources) || return 1
            if [[ -n "$interfaces$sources" ]]; then
                zones+="$zone"$'\n'
            fi
        done
    fi
    while IFS= read -r zone; do
        [[ -n "$zone" ]] && FW_ZONES+=("$zone")
    done < <(printf '%s\n%s\n' "$default_zone" "$zones" | awk 'NF && !seen[$1]++ {print $1}')
}

iptables_allow() {
    local tool="$1"
    shift
    "$tool" -C INPUT "$@" 2>/dev/null || "$tool" -I INPUT 1 "$@"
}

fw_allow_port() {
    local port="$1" proto="${2:-tcp}" zone
    validate_port "$port" 1 && [[ "$proto" == tcp || "$proto" == udp ]] || return 1
    case "$FW_TYPE" in
        ufw) ufw allow "$port/$proto" ;;
        firewalld)
            for zone in "${FW_ZONES[@]}"; do
                if firewall-cmd --state &>/dev/null; then
                    if ! firewall-cmd --zone="$zone" --query-port="$port/$proto" >/dev/null; then
                        # 回滚时仅撤销本次新增的运行时规则, 保留管理员原有临时规则。
                        if [[ -n "$ROLLBACK_DIR" ]]; then
                            printf 'firewall-cmd --zone=%q --remove-port=%q\n' "$zone" "$port/$proto" >> "$ROLLBACK_DIR/runtime-undo.sh" || return 1
                        fi
                        firewall-cmd --zone="$zone" --add-port="$port/$proto" || return 1
                    fi
                    firewall-cmd --permanent --zone="$zone" --add-port="$port/$proto" || return 1
                else
                    firewall-offline-cmd --zone="$zone" --add-port="$port/$proto" || return 1
                fi
            done
            ;;
        iptables)
            iptables_allow iptables -p "$proto" --dport "$port" -j ACCEPT || return 1
            if command -v ip6tables &>/dev/null; then
                iptables_allow ip6tables -p "$proto" --dport "$port" -j ACCEPT || return 1
            fi
            ;;
    esac
}

fw_set_defaults() {
    case "$FW_TYPE" in
        ufw)
            ufw default deny incoming && ufw default allow outgoing
            ;;
        firewalld)
            # 保留原有 zone/接口绑定/目标; 默认 public 已拒绝未放行入站。
            info "保留现有 firewalld zone 策略: ${FW_ZONES[*]}"
            ;;
        iptables)
            local tool
            for tool in iptables ip6tables; do
                command -v "$tool" &>/dev/null || continue
                iptables_allow "$tool" -i lo -j ACCEPT || return 1
                iptables_allow "$tool" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
                if [[ "$tool" == ip6tables ]]; then
                    # IPv6 邻居发现、路由通告和 PMTU 依赖 ICMPv6。
                    iptables_allow "$tool" -p ipv6-icmp -j ACCEPT || return 1
                    iptables_allow "$tool" -p udp --sport 547 --dport 546 -j ACCEPT || return 1
                else
                    iptables_allow "$tool" -p icmp -j ACCEPT || return 1
                    iptables_allow "$tool" -p udp --sport 67 --dport 68 -j ACCEPT || return 1
                fi
            done
            # 所有保活规则和 SSH 放行成功之后才改变 INPUT; 不改容器/VPN 转发策略。
            iptables -P INPUT DROP || return 1
            if command -v ip6tables &>/dev/null; then
                ip6tables -P INPUT DROP || return 1
            fi
            ;;
    esac
}

fw_enable() {
    case "$FW_TYPE" in
        ufw) ufw --force enable ;;
        firewalld) systemctl start firewalld ;;
        iptables) return 0 ;;
    esac
}

fw_persist() {
    case "$FW_TYPE:$OS_FAMILY" in
        firewalld:*) systemctl enable firewalld ;;
        iptables:arch)
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/iptables.rules || return 1
            ip6tables-save > /etc/iptables/ip6tables.rules || return 1
            systemctl enable iptables ip6tables
            ;;
        iptables:alpine)
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules-save || return 1
            ip6tables-save > /etc/iptables/rules6-save || return 1
            rc-update add iptables default && rc-update add ip6tables default
            ;;
        iptables:*)
            warn "当前发行版未配置 iptables 开机恢复, 规则仅在本次启动有效"
            ;;
    esac
}

fw_status() {
    case "$FW_TYPE" in
        ufw) ufw status verbose ;;
        firewalld) firewall-cmd --list-all-zones ;;
        iptables) iptables -S INPUT; ip6tables -S INPUT ;;
    esac
}

prepare_firewall_rollback() {
    local dir="$1" active=false
    fw_is_active && active=true
    printf '#!/bin/bash\nset -e\n' > "$dir/runtime-undo.sh" || return 1
    case "$FW_TYPE" in
        ufw|firewalld) cp -a "/etc/$FW_TYPE" "$dir/original" || return 1 ;;
        iptables)
            iptables-save > "$dir/rules.v4" || return 1
            if command -v ip6tables &>/dev/null; then
                ip6tables-save > "$dir/rules.v6" || return 1
            fi
            ;;
    esac
    {
        echo '#!/bin/bash'
        echo 'set -e'
        printf 'dir=%q\nbackend=%q\nactive=%q\n' "$dir" "$FW_TYPE" "$active"
        cat <<'EOF'
if ! mv "$dir/pending" "$dir/rolling-back" 2>/dev/null; then exit 0; fi
case "$backend" in
    ufw|firewalld)
        mv "/etc/$backend" "$dir/failed-config"
        cp -a "$dir/original" "/etc/$backend"
        if [[ "$backend" == ufw ]]; then
            if "$active"; then ufw reload; else ufw --force disable; fi
        elif "$active"; then
            bash "$dir/runtime-undo.sh"
        else
            systemctl stop firewalld
        fi
        ;;
    iptables)
        iptables-restore < "$dir/rules.v4"
        if [[ -f "$dir/rules.v6" ]]; then ip6tables-restore < "$dir/rules.v6"; fi
        ;;
esac
EOF
    } > "$dir/rollback.sh"
}

# ========================== 关键修改的限时回滚 ==========================
# pending 的原子重命名让确认与超时回滚只会有一个成功。
rollback_on_exit() {
    if [[ -n "$ROLLBACK_DIR" ]]; then
        bash "$ROLLBACK_DIR/rollback.sh" || { error "自动回滚失败, 请检查 $ROLLBACK_DIR/rollback.log"; return 1; }
    fi
}

start_rollback_guard() {
    ROLLBACK_DIR="$1"
    touch "$ROLLBACK_DIR/pending" || return 1
    trap rollback_on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    nohup bash -c 'sleep "$1"; exec bash "$2/rollback.sh"' _ \
        "$ROLLBACK_SECONDS" "$ROLLBACK_DIR" >"$ROLLBACK_DIR/rollback.log" 2>&1 </dev/null &
    info "${ROLLBACK_SECONDS} 秒内未确认会自动回滚; 备份: $ROLLBACK_DIR"
}

finish_rollback_guard() {
    local result=0
    mv "$ROLLBACK_DIR/pending" "$ROLLBACK_DIR/confirmed" 2>/dev/null || result=1
    ROLLBACK_DIR=""
    trap - EXIT INT TERM HUP
    return "$result"
}

cancel_rollback_guard() {
    rollback_on_exit || return 1
    ROLLBACK_DIR=""
    trap - EXIT INT TERM HUP
}

# ========================== SSH 服务操作 ==========================
ssh_restart() {
    # 优先 reload, 保留现有会话; socket 激活的端口修改在阶段 4 单独拦截。
    if command -v systemctl &>/dev/null && [[ -d /run/systemd/system ]]; then
        systemctl reload "$SSH_SERVICE" || systemctl restart "$SSH_SERVICE"
    elif command -v rc-service &>/dev/null; then
        rc-service sshd reload || rc-service sshd restart
    elif command -v service &>/dev/null; then
        service "$SSH_SERVICE" reload || service "$SSH_SERVICE" restart
    else
        error "无法重新加载 SSH 服务"
        return 1
    fi
}

ssh_syntax_check() {
    sshd -t -f "${1:-$SSHD_CONFIG}"
}

render_ssh_config() {
    local original="$1" settings="$2" output="$3"
    {
        echo '# BEGIN VPS-FIRST MANAGED'
        cat "$settings"
        echo '# END VPS-FIRST MANAGED'
        # 只替换本脚本管理块, 不碰用户的 Match/Include 规则。
        awk '
            $0 == "# BEGIN VPS-FIRST MANAGED" {managed=1; next}
            $0 == "# END VPS-FIRST MANAGED" {managed=0; next}
            !managed {print}
        ' "$original"
    } > "$output"
}

# ========================== 用户创建抽象层 ==========================
grant_sudo() {
    local username="$1" sudo_file="/etc/sudoers.d/90-vps-first-$1"
    command -v sudo &>/dev/null || { pkg_install sudo || return 1; }
    command -v visudo &>/dev/null || return 1
    if ! grep -Eq '^[[:space:]]*([#@]includedir)[[:space:]]+/etc/sudoers.d([[:space:]]|$)' /etc/sudoers; then
        error "sudoers 未启用 /etc/sudoers.d, 请手动配置后再禁用 root"
        return 1
    fi
    if [[ -e "$sudo_file" ]]; then
        visudo -cf /etc/sudoers || return 1
    else
        mkdir -p /etc/sudoers.d
        local tmp
        tmp=$(mktemp /etc/sudoers.d/.vps-first.XXXXXX) || return 1
        printf '%s ALL=(ALL:ALL) ALL\n' "$username" > "$tmp"
        chmod 440 "$tmp"
        if ! visudo -cf "$tmp"; then
            rm -f "$tmp"
            return 1
        fi
        mv "$tmp" "$sudo_file" || return 1
        if ! visudo -cf /etc/sudoers; then
            mv "$sudo_file" "${sudo_file}.invalid"
            return 1
        fi
    fi
    success "sudo 规则已检查; 仍需使用该用户实际执行 sudo -v 验证"
}

create_system_user() {
    local username="$1"
    case "$OS_FAMILY" in
        debian) adduser --gecos "" "$username" || return 1 ;;
        rhel|arch|suse)
            useradd -m -s /bin/bash "$username" || return 1
            info "请为用户 '$username' 设置密码:"
            passwd "$username" || return 1
            ;;
        alpine) adduser -s /bin/ash "$username" || return 1 ;;
    esac
    grant_sudo "$username"
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
            if ! semanage port -l | awk -v port="$NEW_SSH_PORT" '
                $1=="ssh_port_t" && $2=="tcp" {for(i=3;i<=NF;i++) {gsub(/,/, "", $i); if($i==port) found=1}}
                END {exit !found}'; then
                if ! semanage port -a -t ssh_port_t -p tcp "$NEW_SSH_PORT"; then
                    warn "SELinux 端口注册失败, 跳过 SSH 修改 (不覆盖其他服务的端口类型)"
                    return 1
                fi
            fi
        else
            warn "semanage 未安装, 无法自动配置 SELinux SSH 端口"
            warn "请手动安装: $(
                case $OS_FAMILY in
                    rhel) echo 'dnf install policycoreutils-python-utils' ;;
                    *)    echo 'policycoreutils-python-utils' ;;
                esac
            )"
            warn "然后执行: semanage port -a -t ssh_port_t -p tcp $NEW_SSH_PORT"
            return 1
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
            pkg_install unattended-upgrades || return 1
            if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
                cp -p /etc/apt/apt.conf.d/20auto-upgrades "/etc/apt/apt.conf.d/20auto-upgrades.bak.$(date +%s)" || return 1
            fi
            echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades
            success "自动安全更新已启用 (unattended-upgrades)"
            ;;
        rhel)
            if command -v dnf &>/dev/null; then
                pkg_install dnf-automatic || return 1
                [[ -f /etc/dnf/automatic.conf ]] || return 1
                cp -p /etc/dnf/automatic.conf "/etc/dnf/automatic.conf.bak.$(date +%s)" || return 1
                # 仅安装安全更新
                sed -i 's/^upgrade_type\s*=.*/upgrade_type = security/' /etc/dnf/automatic.conf 2>/dev/null || true
                sed -i 's/^apply_updates\s*=.*/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null || true
                systemctl enable --now dnf-automatic.timer || return 1
                success "自动安全更新已启用 (dnf-automatic)"
            else
                pkg_install yum-cron || return 1
                [[ -f /etc/yum/yum-cron.conf ]] || return 1
                cp -p /etc/yum/yum-cron.conf "/etc/yum/yum-cron.conf.bak.$(date +%s)" || return 1
                sed -i 's/^update_cmd\s*=.*/update_cmd = security/' /etc/yum/yum-cron.conf 2>/dev/null || true
                sed -i 's/^apply_updates\s*=.*/apply_updates = yes/' /etc/yum/yum-cron.conf 2>/dev/null || true
                systemctl enable --now yum-cron || return 1
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
    command -v sshd &>/dev/null && [[ -f "$SSHD_CONFIG" ]] || {
        error "未找到 OpenSSH 服务端或配置文件, 无法安全初始化"
        return 1
    }
    ssh_syntax_check || return 1

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

# ========================== EOL 源提示 ==========================
fix_eol_repos() {
    # 旧版本号、网络超时、镜像维护都不足以证明应当切换仓库。
    # 不关闭全局签名/有效期检查, 也不改第三方仓库和 deb822 sources。
    warn "归档源不能恢复安全更新; 建议先迁移到受支持的发行版"
    case "$OS_ID" in
        centos) info "CentOS 归档索引: https://vault.centos.org/" ;;
        debian) info "Debian 归档索引: https://archive.debian.org/debian/" ;;
        ubuntu) info "Ubuntu 归档索引: https://old-releases.ubuntu.com/ubuntu/" ;;
        fedora) info "Fedora 归档索引: https://archives.fedoraproject.org/pub/archive/fedora/linux/" ;;
        *) info "请按发行版官方文档检查软件源" ;;
    esac
    info "请确认具体版本和源文件格式后手动修复, 脚本不会自动改写软件源"
}

# ========================== 阶段 1: 系统更新与工具安装 ==========================
phase1_system_update() {
    step "阶段 1/7: 系统更新与基础工具安装"

    # --- 可选查看旧版系统的软件源说明 ---
    if confirm "是否查看 EOL 旧版系统的软件源说明?" "n"; then
        fix_eol_repos
    fi

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

    if id "$username" &>/dev/null && [[ "$(id -u "$username")" == 0 ]]; then
        warn "必须选择 UID 不为 0 的用户; 保持当前 root 配置"
        return 0
    fi
    if id "$username" &>/dev/null; then
        warn "用户 '$username' 已存在"
        if confirm "是否直接使用该用户继续?"; then
            NEW_USER="$username"
            grant_sudo "$username" || warn "sudo 权限尚未就绪, 不会自动禁用 root"
            success "将使用已有用户: $username"
            return 0
        else
            error "请重新运行脚本并选择其他用户名"
            exit 1
        fi
    fi

    info "正在创建用户 '$username'..."
    if ! create_system_user "$username"; then
        warn "用户创建或 sudo 配置未完成, 保持 root 登录设置"
        return 0
    fi
    success "用户 '$username' 已创建"

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

    SSH_KEY_CONFIGURED=false
    SUDO_VERIFIED=false
    if ! confirm "你是否已经准备好 SSH 公钥?"; then
        warn "跳过 SSH 密钥配置"
        warn "后续保持现有密码登录设置"
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
    user_home=$(get_user_home "$target_user")
    [[ -n "$user_home" && -d "$user_home" ]] || { error "用户主目录不存在"; return 1; }
    local ssh_dir="$user_home/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"

    if [[ -L "$ssh_dir" || -L "$auth_keys" ]]; then
        warn "SSH 目录或 authorized_keys 是符号链接, 请手动安装公钥"
        return 0
    fi
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"

    if [ -f "$auth_keys" ] && grep -qxF "$pubkey" "$auth_keys" 2>/dev/null; then
        warn "该公钥已存在于 authorized_keys 中, 无需重复添加"
    else
        if [[ -f "$auth_keys" ]]; then
            cp -p "$auth_keys" "${auth_keys}.bak.$(date +%Y%m%d%H%M%S)"
        fi
        # 兼容旧文件最后一行没有换行符。
        printf '\n%s\n' "$pubkey" >> "$auth_keys"
        success "公钥已写入 $auth_keys"
    fi

    chmod 600 "$auth_keys"
    chown "${target_user}:$(id -gn "$target_user")" "$ssh_dir" "$auth_keys"

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
    echo -e "  ${CYAN}ssh -o ControlMaster=no -o ControlPath=none -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -p $current_port ${NEW_USER:-root}@${server_ip}${NC}"
    echo ""
    echo -e "${YELLOW}请确认: 不需要输入 服务器密码 就能登录成功${NC}"
    echo -e "${YELLOW}(如果给私钥设了 passphrase, 会提示输入私钥密码, 这是正常的)${NC}"
    echo ""

    if confirm "密钥登录测试是否成功? (一定要先测试再回答!)" "n"; then
        SSH_KEY_CONFIGURED=true
        success "SSH 密钥验证通过"
        if [[ -n "$NEW_USER" ]]; then
            info "请在新用户终端执行 sudo -k; sudo -v, 确认能够提权"
            if confirm "新用户 sudo -v 是否成功?" "n"; then
                SUDO_VERIFIED=true
            fi
        fi
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
        warn "现有密码登录设置不会被改动"
    fi
}

# ========================== 阶段 4: SSH 安全加固 ==========================
phase4_ssh_harden() {
    step "阶段 4/7: SSH 安全加固"
    local current_port new_port ports
    current_port=$(get_current_ssh_port)
    NEW_SSH_PORT="$current_port"
    ports=$(get_configured_ssh_ports) || return 1
    new_port="$current_port"
    info "当前连接端口: $current_port; sshd 配置端口: ${ports//$'\n'/, }"

    if confirm "是否增加新的 SSH 端口? (保留原端口便于恢复)" "n"; then
        if systemctl is-active --quiet ssh.socket 2>/dev/null ||
           systemctl is-active --quiet sshd.socket 2>/dev/null; then
            warn "检测到 SSH socket 激活; 本脚本保留端口, 请另行配置 socket 监听地址"
        else
            read -rp "新端口 (1024-65535) [默认: $DEFAULT_SSH_PORT]: " new_port
            new_port="${new_port:-$DEFAULT_SSH_PORT}"
            if validate_port "$new_port"; then
                new_port=$((10#$new_port))
            else
                warn "端口不合法, 保持 $current_port"
                new_port="$current_port"
            fi
        fi
    fi

    local tmp_dir settings candidate
    tmp_dir=$(mktemp -d "${SSHD_CONFIG}.vps-first.XXXXXX")
    settings="$tmp_dir/settings"
    candidate="$tmp_dir/candidate"
    # Port 是可多次设置的选项, 保留已有管理块里的端口。
    { printf '%s\n' "$ports"; echo "$current_port"; echo "$new_port"; } |
        awk 'NF && !seen[$1]++ {print "Port " $1}' > "$settings"
    cat >> "$settings" <<'EOF'
PubkeyAuthentication yes
MaxAuthTries 3
PermitEmptyPasswords no
EOF
    if [[ "$SSH_KEY_CONFIGURED" == true ]]; then
        cat >> "$settings" <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
EOF
        # root 继续用密钥时不再允许其密码登录。
        if [[ -z "$NEW_USER" ]]; then
            local current_root
            current_root=$(ssh_effective_config root | awk '$1=="permitrootlogin" {print $2}') || return 1
            if [[ "$current_root" != no ]]; then
                echo 'PermitRootLogin prohibit-password' >> "$settings"
            fi
        elif [[ "$SUDO_VERIFIED" == true ]]; then
            echo 'PermitRootLogin no' >> "$settings"
        fi
    fi
    # 未验证的认证选项保持现状, 包括之前已关闭的密码/root 登录。
    # 重跑时保留旧管理块里本轮没有重新决定的设置。
    awk 'NR==FNR {keys[tolower($1)]=1; next}
        $0 == "# BEGIN VPS-FIRST MANAGED" {managed=1; next}
        $0 == "# END VPS-FIRST MANAGED" {managed=0; next}
        managed && NF && !keys[tolower($1)] {print}' "$settings" "$SSHD_CONFIG" > "$tmp_dir/retained"
    cat "$tmp_dir/retained" >> "$settings"
    render_ssh_config "$SSHD_CONFIG" "$settings" "$candidate"
    if ! ssh_syntax_check "$candidate"; then
        error "候选 SSH 配置未通过语法检查, 原配置未修改"
        return 0
    fi
    local effective
    effective=$(ssh_effective_config "${NEW_USER:-root}" "$candidate" "$new_port") || return 1
    if [[ "$SSH_KEY_CONFIGURED" == true ]] &&
       ! awk '$1=="passwordauthentication" && $2=="no" {p=1}
             $1=="kbdinteractiveauthentication" && $2=="no" {k=1}
             $1=="pubkeyauthentication" && $2=="yes" {a=1}
             END {exit !(p && k && a)}' <<< "$effective"; then
        warn "现有 Match/Include 规则覆盖了目标用户的认证设置, 本次 SSH 修改已跳过"
        return 0
    fi
    if [[ "$SUDO_VERIFIED" == true && -n "$NEW_USER" ]] &&
       [[ "$(ssh_effective_config root "$candidate" "$new_port" | awk '$1=="permitrootlogin" {print $2}')" != no ]]; then
        warn "现有 Match 规则覆盖了 root 登录限制, 本次 SSH 修改已跳过"
        return 0
    fi
    info "将应用以下配置 (现有端口继续监听):"
    cat "$settings"
    if [[ "$new_port" != "$current_port" ]]; then
        warn "请先在云安全组和已有系统防火墙放行 $new_port/tcp"
        if ! confirm "新端口是否已放行?" "n"; then
            warn "跳过 SSH 修改"
            return 0
        fi
    fi
    if ! confirm "确认应用以上 SSH 配置?" "n"; then
        return 0
    fi

    NEW_SSH_PORT="$new_port"
    if ! handle_selinux_ssh; then
        NEW_SSH_PORT="$current_port"
        return 0
    fi
    cp -p "$SSHD_CONFIG" "$tmp_dir/original" || return 1
    {
        echo '#!/bin/bash'
        printf 'dir=%q\nconfig=%q\nSSH_SERVICE=%q\n' "$tmp_dir" "$SSHD_CONFIG" "$SSH_SERVICE"
        declare -f ssh_restart error
        printf 'RED=%q\nNC=%q\n' "$RED" "$NC"
        cat <<'EOF'
if mv "$dir/pending" "$dir/rolling-back" 2>/dev/null; then
    cp -p "$dir/original" "$config" && ssh_restart
fi
EOF
    } > "$tmp_dir/rollback.sh"
    start_rollback_guard "$tmp_dir" || return 1
    if ! cat "$candidate" > "$SSHD_CONFIG" || ! ssh_syntax_check || ! ssh_restart; then
        error "SSH 配置应用失败, 正在还原"
        cancel_rollback_guard
        NEW_SSH_PORT="$current_port"
        return 0
    fi
    warn "不要关闭当前终端; 请新开终端测试实际登录"
    echo "  ssh -o ControlMaster=no -o ControlPath=none -p $new_port ${NEW_USER:-root}@$(get_server_ip)"
    if confirm "新终端登录和 sudo (非 root 用户) 均成功?" "n"; then
        if finish_rollback_guard; then
            success "SSH 加固完成; 原端口仍保留, 验证后可手动清理"
        else
            warn "已超过确认时间, SSH 配置已自动回滚"
            NEW_SSH_PORT="$current_port"
        fi
    else
        cancel_rollback_guard
        NEW_SSH_PORT="$current_port"
        warn "SSH 配置已回滚"
    fi
}

# ========================== 阶段 5: 防火墙 ==========================
phase5_firewall() {
    step "阶段 5/7: 防火墙配置"
    # 优先使用已经运行的管理器, 避免叠加多套防火墙。
    if firewall-cmd --state &>/dev/null; then
        if LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active'; then
            warn "ufw 与 firewalld 同时运行, 请先统一防火墙管理方式; 跳过自动修改"
            return 0
        fi
        FW_TYPE=firewalld
    elif LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active'; then
        FW_TYPE=ufw
    elif command -v ufw &>/dev/null; then
        FW_TYPE=ufw
    elif command -v firewall-cmd &>/dev/null; then
        FW_TYPE=firewalld
    elif command -v iptables &>/dev/null; then
        FW_TYPE=iptables
    else
        warn "没有可用的防火墙工具, 跳过"
        return 0
    fi
    if [[ "$FW_TYPE" == iptables ]] && systemctl is-active --quiet nftables 2>/dev/null; then
        warn "检测到独立 nftables 服务, 请在现有规则中配置; 跳过 iptables 修改"
        return 0
    fi
    if [[ "$FW_TYPE" == iptables && -s /proc/net/if_inet6 ]] && ! command -v ip6tables &>/dev/null; then
        warn "系统启用了 IPv6 但缺少 ip6tables, 跳过不完整的防火墙配置"
        return 0
    fi
    info "使用防火墙: $FW_TYPE"
    confirm "是否配置防火墙?" || return 0
    if [[ "$FW_TYPE" == firewalld ]]; then
        fw_prepare_zones || return 1
    fi

    local ports port extra_port proto
    local rules=()
    ports=$(get_configured_ssh_ports) || return 1
    # 保留全部 sshd 端口和当前会话端口, 避免只保留一个猜测出的 22。
    while IFS= read -r port; do
        [[ -n "$port" ]] && rules+=("$port/tcp")
    done < <(printf '%s\n%s\n%s\n' "$ports" "$(get_current_ssh_port)" "$NEW_SSH_PORT" |
        awk 'NF && !seen[$1]++ {print $1}')
    if confirm "是否放行 HTTP (80) 和 HTTPS (443) 端口?" "n"; then
        rules+=(80/tcp 443/tcp)
    fi
    while confirm "是否需要放行其他端口?" "n"; do
        read -rp "请输入端口号: " extra_port
        if ! validate_port "$extra_port" 1; then
            warn "端口号不合法, 跳过"
            continue
        fi
        extra_port=$((10#$extra_port))
        read -rp "协议 [tcp/udp/both, 默认 tcp]: " proto
        proto="${proto:-tcp}"
        case "$proto" in
            tcp|udp) rules+=("$extra_port/$proto") ;;
            both) rules+=("$extra_port/tcp" "$extra_port/udp") ;;
            *) warn "协议不合法, 跳过" ;;
        esac
    done
    info "将放行: ${rules[*]}"
    info "现有放行规则会保留; firewalld 保留原 zone 策略"
    confirm "确认应用并启用防火墙?" "n" || return 0

    local backup rule failed=false
    backup=$(mktemp -d /etc/vps-first-firewall.XXXXXX)
    prepare_firewall_rollback "$backup" || return 1
    start_rollback_guard "$backup" || return 1
    for rule in "${rules[@]}"; do
        if ! fw_allow_port "${rule%/*}" "${rule#*/}"; then
            failed=true
            break
        fi
    done
    if "$failed" || ! fw_set_defaults || ! fw_enable; then
        error "防火墙配置失败, 正在恢复之前的规则"
        cancel_rollback_guard
        return 0
    fi
    warn "请在新终端重新 SSH 登录, 确认网络正常"
    echo "  ssh -o ControlMaster=no -o ControlPath=none -p ${NEW_SSH_PORT:-$(get_current_ssh_port)} ${NEW_USER:-root}@$(get_server_ip)"
    if confirm "新终端连接是否成功?" "n"; then
        if finish_rollback_guard; then
            fw_persist || warn "开机持久化失败, 请检查防火墙服务"
            fw_status || true
            success "防火墙已应用"
        else
            warn "已超时, 防火墙已回滚"
        fi
    else
        cancel_rollback_guard
        warn "防火墙已回滚"
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
            _configure_swap "$total_mem" || warn "Swap 配置未完成"
        fi
    else
        warn "当前没有 Swap!"
        info "物理内存: ${total_mem}MB"
        if (( total_mem <= 2048 )); then
            warn "内存 <= 2GB, 强烈建议配置 Swap, 否则内存耗尽时进程会被直接杀掉"
        fi
        if confirm "是否配置 Swap?"; then
            _configure_swap "$total_mem" || warn "Swap 配置未完成"
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
            modprobe tcp_bbr 2>/dev/null || true
            if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
                if _sysctl_set net.ipv4.tcp_congestion_control bbr && _sysctl_set net.core.default_qdisc fq; then
                    success "BBR 已开启"
                else
                    warn "BBR 配置未完全生效, 请检查当前内核和容器限制"
                fi
            else
                warn "当前内核未提供 BBR, 跳过"
            fi
        fi
    fi

    if confirm "是否应用内核网络调优参数? (优化 Web 服务器性能)" "n"; then
        _configure_kernel_network || warn "部分连接队列参数未生效"
    fi

    # ======================================================================
    #  6.5 fail2ban 防暴力破解
    # ======================================================================
    echo -e "\n${BOLD}[6.5 fail2ban 防暴力破解]${NC}"
    if ! command -v fail2ban-client &>/dev/null; then
        warn "fail2ban 未安装, 跳过配置"
    elif confirm "是否配置 fail2ban?"; then
        _configure_fail2ban || warn "fail2ban 配置未完成, 请检查上方错误"

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
    echo -e "\n${BOLD}[6.7 命令历史增强 (历史查询)]${NC}"
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
        setup_auto_updates || warn "自动更新配置未完成"
    fi
}

# ---- fail2ban: 独立 drop-in, 不覆盖其他 jail ----
_configure_fail2ban() {
    local maxretry bantime findtime
    read -rp "最大尝试次数 [默认: 3]: " maxretry
    read -rp "封禁时间(秒) [默认: 3600]: " bantime
    read -rp "检测窗口(秒) [默认: 600]: " findtime
    maxretry="${maxretry:-3}"; bantime="${bantime:-3600}"; findtime="${findtime:-600}"
    local value
    for value in "$maxretry" "$bantime" "$findtime"; do
        if [[ ! "$value" =~ ^[0-9]{1,8}$ ]] || (( 10#$value < 1 )); then
            error "fail2ban 参数必须为正整数"
            return 1
        fi
    done
    local backend="$F2B_BACKEND" logpath="$F2B_LOGPATH" ports
    if [[ -d /run/systemd/system ]] && [[ ! -f "$logpath" ]]; then
        backend=systemd
    fi
    if [[ "$backend" != systemd && ! -f "$logpath" ]]; then
        warn "找不到 SSH 日志 $logpath, 请先配置系统日志"
        return 1
    fi
    ports=$(get_configured_ssh_ports | paste -sd, -) || return 1
    local conf=/etc/fail2ban/jail.d/99-vps-first.local backup
    mkdir -p /etc/fail2ban/jail.d
    backup=$(mktemp -d /etc/fail2ban/.vps-first.XXXXXX) || return 1
    if [[ -f "$conf" ]]; then cp -p "$conf" "$backup/original" || return 1; fi
    {
        echo '[sshd]'
        echo 'enabled = true'
        echo "port = $ports"
        echo "backend = $backend"
        [[ "$backend" == systemd ]] || echo "logpath = $logpath"
        echo "maxretry = $((10#$maxretry))"
        echo "bantime = $((10#$bantime))"
        echo "findtime = $((10#$findtime))"
    } > "$conf"
    if ! fail2ban-client -t || ! restart_fail2ban; then
        error "fail2ban 配置检查或启动失败, 还原本次 drop-in"
        if [[ -f "$backup/original" ]]; then
            cp -p "$backup/original" "$conf"
        else
            mv "$conf" "$backup/failed.local"
        fi
        restart_fail2ban || true
        return 1
    fi
    if [[ -d /run/systemd/system ]]; then
        systemctl enable fail2ban || return 1
    elif command -v rc-update &>/dev/null; then
        rc-update add fail2ban default || return 1
    fi
    success "fail2ban 已配置; 其他 jail 保持原样"
}

restart_fail2ban() {
    if [[ -d /run/systemd/system ]]; then
        systemctl restart fail2ban
    elif command -v rc-service &>/dev/null; then
        rc-service fail2ban restart
    else
        service fail2ban restart
    fi
}

# ---- Swap 配置实现 ----
_configure_swap() (
    # 独立子 shell 的清理 trap 不覆盖 SSH/防火墙的回滚 trap。
    local total_mem="$1" recommended_swap swap_size
    [[ "$total_mem" =~ ^[0-9]+$ ]] && (( total_mem > 0 )) || return 1
    if (( total_mem <= 1024 )); then
        recommended_swap=$((total_mem * 2))
    elif (( total_mem <= 4096 )); then
        recommended_swap=$total_mem
    else
        recommended_swap=$((total_mem / 2))
    fi
    (( recommended_swap < 256 )) && recommended_swap=256
    local swapfile="/swapfile"
    if [[ -e "$swapfile" || -L "$swapfile" ]]; then
        warn "$swapfile 已存在, 保留原文件; 调整大小请另行维护"
        return 0
    fi
    read -rp "Swap 大小(MB) [默认: $recommended_swap]: " swap_size
    swap_size="${swap_size:-$recommended_swap}"
    if [[ ! "$swap_size" =~ ^[0-9]{1,8}$ ]] || (( 10#$swap_size < 256 )); then
        warn "Swap 大小不合法 (最小 256MB)"
        return 0
    fi
    swap_size=$((10#$swap_size))
    local free_disk fs_type
    free_disk=$(df -Pm / | awk 'NR==2 {print $4}')
    if (( swap_size > free_disk - 1024 )); then
        warn "磁盘空间不足, 创建后必须至少保留 1GB"
        return 0
    fi
    fs_type=$(stat -f -c %T /)
    case "$fs_type" in
        ext2/ext3|xfs) ;;
        *) warn "文件系统 $fs_type 需要单独确认 Swap 文件支持, 跳过自动创建"; return 0 ;;
    esac
    umask 077
    (set -o noclobber; : > "$swapfile") || return 1
    trap 'if ! awk '\''NR>1 && $1=="/swapfile" {found=1} END {exit !found}'\'' /proc/swaps; then rm -f /swapfile; fi' EXIT
    # BusyBox dd 不支持 status=progress; 写入前文件已限制为 root 可读写。
    if ! dd if=/dev/zero of="$swapfile" bs=1M count="$swap_size" ||
       ! mkswap "$swapfile" || ! swapon "$swapfile"; then
        error "Swap 创建/启用失败, 不写入 fstab"
        return 1
    fi
    if ! awk '$1=="/swapfile" && $3=="swap" {found=1} END {exit !found}' /etc/fstab; then
        cp -p /etc/fstab "/etc/fstab.bak.$(date +%Y%m%d%H%M%S)" || return 1
        printf '\n/swapfile none swap sw 0 0\n' >> /etc/fstab || return 1
    fi
    _sysctl_set vm.swappiness 10 || true
    _sysctl_set vm.vfs_cache_pressure 50 || true
    success "Swap 已启用: ${swap_size}MB"
)

# ---- Locale 配置实现 ----
_configure_locale() {
    local target_locale="en_US.UTF-8"

    case "$OS_FAMILY" in
        debian)
            # 生成 locale
            if command -v locale-gen &>/dev/null; then
                sed -i "s/^# *${target_locale}/${target_locale}/" /etc/locale.gen 2>/dev/null || true
                grep -qxF "$target_locale UTF-8" /etc/locale.gen || echo "$target_locale UTF-8" >> /etc/locale.gen
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
    info "调整连接队列; 实际收益取决于应用并发和内存, 建议先压测"
    _sysctl_set net.core.somaxconn 4096 || return 1
    _sysctl_set net.core.netdev_max_backlog 4096 || return 1
    _sysctl_set net.ipv4.tcp_max_syn_backlog 4096 || return 1
    success "连接队列参数已应用"
}

# ---- 只应用本次键, 不重载系统其他 sysctl 配置 ----
_sysctl_set() {
    local key="$1" value="$2" conf=/etc/sysctl.d/99-vps-first.conf
    if ! sysctl -w "$key=$value" >/dev/null; then
        warn "当前内核不支持或不允许修改 $key, 未写入持久配置"
        return 1
    fi
    mkdir -p /etc/sysctl.d
    local tmp
    tmp=$(mktemp /etc/sysctl.d/.vps-first.XXXXXX) || return 1
    if [[ -f "$conf" ]]; then
        cp -p "$conf" "${tmp}.backup" || return 1
        awk -F= -v key="$key" '{name=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", name); if(name!=key) print}' "$conf" > "$tmp"
    fi
    printf '%s = %s\n' "$key" "$value" >> "$tmp"
    chmod 644 "$tmp"
    mv "$tmp" "$conf"
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
# /etc/profile.d 也会被非 Bash shell 读取。
if [ -n "${BASH_VERSION:-}" ]; then
    shopt -s histappend
    if ! declare -p PROMPT_COMMAND 2>/dev/null | grep -q 'declare -a'; then
        case "${PROMPT_COMMAND:-}" in
            *"history -a"*) ;;
            *) PROMPT_COMMAND="history -a; ${PROMPT_COMMAND:-}" ;;
        esac
    fi
fi
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
        _check_item "ok" "用户 '${NEW_USER}' (sudo 已实测: $SUDO_VERIFIED)"
    elif [[ -z "${NEW_USER:-}" ]]; then
        _check_item "warn" "使用 root 登录 (未创建独立用户)"
    else
        _check_item "fail" "未创建非 root 用户"
    fi

    # 3. SSH 密钥
    local user_home
    user_home=$(get_user_home "${NEW_USER:-root}")
    local auth_file="$user_home/.ssh/authorized_keys"
    if [ -f "$auth_file" ] && [ -s "$auth_file" ]; then
        _check_item "ok" "SSH 公钥已配置"
    else
        _check_item "fail" "SSH 公钥未配置"
    fi

    # 4. 密码登录状态
    local pass_auth kbd_auth effective
    effective=$(ssh_effective_config) || return 1
    pass_auth=$(awk '$1=="passwordauthentication" {print $2}' <<< "$effective")
    kbd_auth=$(awk '$1=="kbdinteractiveauthentication" {print $2}' <<< "$effective")
    if [[ "$pass_auth" == no && "$kbd_auth" == no ]]; then
        _check_item "ok" "目标用户密码及交互认证已禁用"
    else
        _check_item "warn" "目标用户仍允许密码或交互认证"
    fi

    # 5. Root 登录
    local root_login
    root_login=$(ssh_effective_config root | awk '$1=="permitrootlogin" {print $2}')
    if [[ "$root_login" == "no" ]]; then
        _check_item "ok" "Root SSH 已禁止"
    else
        _check_item "warn" "Root SSH 仍然允许"
    fi

    # 6. SSH 端口
    local ssh_port
    ssh_port="${NEW_SSH_PORT:-$(get_current_ssh_port)}"
    _check_item "ok" "SSH 配置端口: $(get_configured_ssh_ports | paste -sd, -) (运行端口需实测)"

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
    if fail2ban-client ping &>/dev/null; then
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
    echo "  SSH 备份:       /etc/ssh/sshd_config.vps-first.*/original"
    echo "  授权密钥:       $user_home/.ssh/authorized_keys"
    echo "  fail2ban:       /etc/fail2ban/jail.d/99-vps-first.local"
    echo "  内核参数:       /etc/sysctl.d/99-vps-first.conf"

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

    if ! confirm "是否下载并运行 GitHub 上的 SSH 登录美化脚本?" "n"; then
        info "跳过 ssh_hello 安装"
        return 0
    fi

    info "正在下载 ssh_hello..."
    local tmp_script
    tmp_script=$(mktemp)

    # 使用项目原始 HTTPS 地址, HTTP 错误码不能当作脚本执行。
    if curl -o "$tmp_script" -fsSL --max-time 15 \
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

    if [[ ! -s "$tmp_script" ]] || ! bash -n "$tmp_script"; then
        error "下载文件为空, 跳过"
        rm -f "$tmp_script"
        return 0
    fi

    info "启动 ssh_hello 安装向导 (按提示输入自定义文本和颜色)..."
    echo ""
    if ! bash "$tmp_script"; then
        rm -f "$tmp_script"
        warn "ssh_hello 安装未完成"
        return 0
    fi
    rm -f "$tmp_script"

    echo ""
    success "ssh_hello 安装完成! 重新 SSH 连接即可看到效果"
}

# ========================== 主流程 ==========================
main() {
    [[ "$EUID" -eq 0 ]] || { error "请以 root 身份运行: sudo bash $0"; return 1; }
    [[ "$(uname -s)" == Linux ]] || { error "此脚本仅支持 Linux"; return 1; }
    [[ "${BASH_VERSINFO[0]}" -ge 4 ]] || { error "需要 Bash 4 或更新版本"; return 1; }
    [[ -t 0 ]] || { error "需要交互终端; 请下载后运行 bash vps-init.sh"; return 1; }
    umask 022
    clear 2>/dev/null || true
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

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -euo pipefail
    main "$@"
fi
