#!/usr/bin/env bash

# Self-logging: line-buffered tee to /vagrant/provision.log (VM only)
if [ -d /vagrant ]; then
    exec > >(stdbuf -oL tee -a /vagrant/provision.log) 2>&1
fi
echo "=== provision.sh started at $(date) ==="

# When run by vagrant provision, BASH_SOURCE is /tmp/vagrant-shell — use /vagrant/scripts
if [[ "${BASH_SOURCE[0]}" == /tmp/* ]]; then
    SCRIPT_DIR="/vagrant/scripts"
else
    SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd -P)
fi

echo "${SCRIPT_DIR}"

fun_chmirror() {
    if command -v apt ; then
        if grep ubuntu /etc/os-release; then
            
            if [ -e /etc/apt/sources.list ]; then
            sed -i \
            -e 's@//.*archive.ubuntu.com@//mirrors.ustc.edu.cn@g' \
            -e 's@security.ubuntu.com@mirrors.ustc.edu.cn@g' /etc/apt/sources.list
            fi

            if [ -e /etc/apt/sources.list.d/ubuntu.sources ]; then
            sed -i \
            -e 's@//.*archive.ubuntu.com@//mirrors.ustc.edu.cn@g' \
            -e 's@security.ubuntu.com@mirrors.ustc.edu.cn@g' /etc/apt/sources.list.d/ubuntu.sources
            fi
        elif grep debian /etc/os-release; then
            if [ -e /etc/apt/sources.list ]; then
            sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && \
            sed -i -e 's|security.debian.org/\? |security.debian.org/debian-security |g' \
                        -e 's|security.debian.org|mirrors.ustc.edu.cn|g' \
                        -e 's|deb.debian.org/debian-security|mirrors.ustc.edu.cn/debian-security|g' \
                        /etc/apt/sources.list
            fi

            if [ -e /etc/apt/sources.list.d/ubuntu.sources ]; then
            sed -i \
            -e 's/deb.debian.org/mirrors.ustc.edu.cn/g' \
            -e 's/security.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources
            fi
        fi
    fi
}


fun_system() {

## 设置时区

timedatectl set-timezone "Asia/Shanghai"

## 关闭防火墙

if systemctl is-active firewalld >/dev/null 2>&1; then systemctl disable --now firewalld; fi
if systemctl is-active dnsmasq >/dev/null 2>&1; then systemctl disable --now dnsmasq; fi
if systemctl is-active apparmor >/dev/null 2>&1; then systemctl disable --now apparmor; fi
if systemctl is-active ufw >/dev/null 2>&1; then systemctl disable --now ufw; fi

## 关闭swap

#sed -ri 's/.*swap.*/#&/' /etc/fstab
swapoff -a && sysctl -w vm.swappiness=0
sed -ri '/^[^#]*swap/s@^@#@' /etc/fstab

## 关闭selinux

if [ -f /etc/selinux/config ]; then sed -i.bak 's@enforcing@disabled@' /etc/selinux/config; fi
if command -v setenforce; then setenforce 0; fi
if command -v getenforce; then getenforce; fi
if command -v sestatus; then sestatus; fi

## sysctl设置

cat > /etc/sysctl.d/mysysctl.conf << 'EOF'
fs.file-max = 52706963 
fs.inotify.max_queued_events = 16384
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 1048576
fs.may_detach_mounts = 1
fs.nr_open = 52706963
kernel.core_uses_pid = 1
kernel.msgmax = 65535
kernel.msgmnb = 65535 
kernel.pid_max = 4194303 
kernel.shmall = 4294967296
kernel.shmmax = 68719476736
kernel.softlockup_all_cpu_backtrace = 1
kernel.softlockup_panic = 1
#kernel.sysrq = 1
net.bridge.bridge-nf-call-arptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.core.netdev_max_backlog = 16384
net.core.rmem_max = 16777216
net.core.somaxconn = 32768
net.core.wmem_max = 16777216
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.route_localnet = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lo.arp_announce = 2
net.ipv4.ip_forward = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.neigh.default.gc_stale_time = 120
net.ipv4.neigh.default.gc_thresh1 = 8192
net.ipv4.neigh.default.gc_thresh2 = 32768
net.ipv4.neigh.default.gc_thresh3 = 65536
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_max_orphans = 32768
net.ipv4.tcp_max_syn_backlog = 8096
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.tcp_orphan_retries = 3
net.ipv4.tcp_retries2 = 2
net.ipv4.tcp_rmem = 4096 12582912 16777216
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_wmem = 4096 12582912 16777216
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.netfilter.nf_conntrack_max = 25000000
net.netfilter.nf_conntrack_tcp_timeout_close = 3
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_established = 180
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 12
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.nf_conntrack_max = 25000000
vm.max_map_count = 262144
vm.min_free_kbytes = 262144
vm.overcommit_memory = 1
vm.panic_on_oom = 0
vm.swappiness = 0
EOF


sysctl --system

## limits 修改

cat > /etc/security/limits.conf <<'EOF'
*       soft        core        unlimited
*       hard        core        unlimited
*       soft        nproc       1000000
*       hard        nproc       1000000
*       soft        nofile      1000000
*       hard        nofile      1000000
*       soft        memlock     32000
*       hard        memlock     32000
*       soft        msgqueue    8192000
*       hard        msgqueue    8192000
root       soft        core        unlimited
root       hard        core        unlimited
root       soft        nproc       1000000
root       hard        nproc       1000000
root       soft        nofile      1000000
root       hard        nofile      1000000
root       soft        memlock     32000
root       hard        memlock     32000
root       soft        msgqueue    8192000
root       hard        msgqueue    8192000
EOF


## 加载linux内核模块

if ! systemctl is-active systemd-modules-load.service >/dev/null 2>&1; then
    systemctl enable systemd-modules-load.service
fi

cat > /etc/modules-load.d/90-net.conf<<EOF
overlay
br_netfilter
EOF

systemctl daemon-reload && systemctl restart systemd-modules-load.service

lsmod

}

fun_install_docker() {
    mkdir -p /usr/local/lib/docker/cli-plugins
    set -x
    curl -fsSL https://ghfast.top/https://github.com/dyrnq/install-docker/raw/main/install-docker.sh | bash -s docker \
    --mirror aliyun \
    --version 29.4.1 \
    --systemd-mirror https://ghfast.top \
    --with-compose \
    --compose-version 5.1.3 \
    --compose-mirror daocloud \
    --compose-prefix /usr/local/lib/docker/cli-plugins && usermod -aG docker vagrant
    docker ps

#    cat /etc/docker/daemon.json && \
#    sed -i "s@https://docker.mirrors.ustc.edu.cn@https://docker.m.daocloud.io@g" /etc/docker/daemon.json && \
#    systemctl restart docker && \
#    cat /etc/docker/daemon.json
}

fun_misc() {
    echo "root:vagrant" | sudo chpasswd
    timedatectl set-timezone "Asia/Shanghai"
    echo "${HOSTNAME}"
    DEBIAN_FRONTEND=noninteractive apt update;
    DEBIAN_FRONTEND=noninteractive apt install -y jq wget curl vim git net-tools netcat-openbsd gosu aria2 build-essential;
    if [ -f "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf" ]; then
        sed -i "s|^PasswordAuthentication.*|PasswordAuthentication yes|g" /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
        systemctl restart sshd
    fi
    sysctl -w vm.max_map_count=2000000
    echo madvise > /sys/kernel/mm/transparent_hugepage/enabled



if command -v apt ; then

OS_ID=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')

case "$OS_ID" in
    "ubuntu")
        mysql_client_pkg="mysql-client-core-8.0"
        ;;
    "debian")
        mysql_client_pkg="mariadb-client-core"
        ;;
    *)
        # 默认处理（可选）
        echo "Unsupported OS: $OS_ID"
        ;;
esac

DEBIAN_FRONTEND=noninteractive apt update;
DEBIAN_FRONTEND=noninteractive apt install "${mysql_client_pkg}" -y;
# DEBIAN_FRONTEND=noninteractive apt install openjdk-21-jdk-headless openjdk-21-jre-headless -y
fi




}

fun_needrestart(){
if grep ID=ubuntu < /etc/os-release ; then
if [ -e /etc/needrestart/conf.d/ ]; then
cat > /etc/needrestart/conf.d/silence_kernel.conf <<'EOF'
$nrconf{kernelhints} = 0;
$nrconf{restart} = 'l';
EOF
cat /etc/needrestart/conf.d/silence_kernel.conf
fi
fi
}



fun_needrestart
fun_chmirror
fun_system
# while true; do
#   fun_install_docker
#   if docker ps;
#     then break;
#   fi
# done
fun_misc

##############################################
# Rust toolchain installation
##############################################

mkdir -p /usr/local/rustup /usr/local/cargo
export RUSTUP_HOME=/usr/local/rustup
export CARGO_HOME=/usr/local/cargo
export RUSTUP_UPDATE_ROOT=https://mirrors.aliyun.com/rustup/rustup
export RUSTUP_DIST_SERVER=https://mirrors.aliyun.com/rustup

if ! command -v rustup >/dev/null 2>&1; then
    RUSTUP_URL="https://mirrors.aliyun.com/rustup/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"
    if curl --connect-timeout 30 --proto '=https' --tlsv1.2 -sSfL "$RUSTUP_URL" -o /tmp/rustup-init 2>/dev/null; then
        chmod +x /tmp/rustup-init && /tmp/rustup-init -y --profile minimal --default-toolchain stable && rm -f /tmp/rustup-init
    else
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    fi
fi

source "${CARGO_HOME}/env"

# Append RUSTUP_HOME and CARGO_HOME to cargo/env so that
# `source /usr/local/cargo/env` is sufficient in all contexts
# (including vagrant ssh -- bash -s non-login shells).
{
  echo ""
  echo "export RUSTUP_HOME=/usr/local/rustup"
  echo "export CARGO_HOME=/usr/local/cargo"
} >> "${CARGO_HOME}/env"

# crates.io mirror
if ! grep -q 'aliyun' "${CARGO_HOME}/config.toml" 2>/dev/null; then
    cat > "${CARGO_HOME}/config.toml" << 'CRATES'
[source.crates-io]
replace-with = 'aliyun'
[source.aliyun]
registry = "sparse+https://mirrors.aliyun.com/crates.io-index/"
CRATES
fi

rustup toolchain install stable --profile minimal 2>/dev/null || true
rustup default stable
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf

chmod -R a+rwX "${CARGO_HOME}" "${RUSTUP_HOME}" 2>/dev/null || true

cat > /etc/profile.d/rust.sh << 'RUSTENV'
export RUSTUP_HOME=/usr/local/rustup
export CARGO_HOME=/usr/local/cargo
export PATH="/usr/local/cargo/bin:$PATH"
RUSTENV
chmod 644 /etc/profile.d/rust.sh

# /etc/environment is read by all login sessions (PAM),
# ensuring RUSTUP_HOME/CARGO_HOME are set even for non-login shells
# (e.g. vagrant ssh -- bash -s).
cat > /etc/environment << 'ENVEOF'
RUSTUP_HOME=/usr/local/rustup
CARGO_HOME=/usr/local/cargo
PATH="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENVEOF

echo "Rust $(rustc --version) installed system-wide"


