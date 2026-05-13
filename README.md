# nft-manager.sh 使用指南

单文件 Bash + nftables 防火墙管理脚本。  
当前 GitHub 仓库只需要保留两个文件：

```text
nft-manager.sh
README.md
```

不需要：

```text
install.sh
nft-manager.core.sh
wrapper / core 双文件结构
```

---

## 1. 功能概览

`nft-manager.sh` 用于个人服务器的 nftables 防火墙管理，核心目标是：

- 初始化 nftables 防火墙配置
- 使用默认拒绝策略保护服务器
- 自动放行 SSH，降低锁死风险
- 管理开放端口
- 管理端口转发
- 生成规则预览
- 使用 `safe-apply` 临时应用规则
- 未确认时自动回滚
- 确认后持久化规则
- 使用 systemd 开机加载规则
- 通过交互菜单完成常用操作

---

## 2. 支持的命令

当前脚本支持以下命令：

```text
init
preview
apply
safe-apply
confirm
auto-rollback
rollback
status
sample
enable-service
disable-service
open-add
open-del
open-list
forward-add
forward-del
forward-list
menu
```

---

## 3. 系统要求

建议系统：

```text
Debian 12 / Debian 13
root 用户
bash
nftables
systemd
```

检查依赖：

```bash
command -v bash
command -v nft
command -v sysctl
command -v systemctl
command -v systemd-run || true
command -v flock
command -v mktemp
command -v awk
command -v grep
```

安装常用依赖：

```bash
apt update
apt install -y bash nftables systemd procps coreutils gawk grep util-linux
```

---

## 4. 新机器首次安装

进入 `/root`：

```bash
cd /root
```

下载脚本：

```bash
wget -O /root/nft-manager.sh \
  https://raw.githubusercontent.com/disabledlifes-svg/self-nftables/refs/heads/main/nft-manager.sh
```

设置权限：

```bash
chmod 700 /root/nft-manager.sh
```

语法检查：

```bash
bash -n /root/nft-manager.sh
```

初始化：

```bash
/root/nft-manager.sh init
```

查看状态：

```bash
/root/nft-manager.sh status
```

---

## 5. 一键初始化命令

新机器可以直接执行这一组：

```bash
cd /root

wget -O /root/nft-manager.sh \
  https://raw.githubusercontent.com/disabledlifes-svg/self-nftables/refs/heads/main/nft-manager.sh

chmod 700 /root/nft-manager.sh

bash -n /root/nft-manager.sh

/root/nft-manager.sh init

/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft

/root/nft-manager.sh safe-apply 120
```

确认 SSH 没有断开后执行：

```bash
/root/nft-manager.sh confirm
```

然后启用开机加载：

```bash
/root/nft-manager.sh enable-service
systemctl is-enabled nft-manager.service
systemctl is-active nft-manager.service
```

---

## 6. 重要安全流程

远程服务器上，推荐始终使用：

```text
preview -> nft -c -> safe-apply -> confirm
```

也就是：

```bash
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

不要在远程服务器上优先使用：

```bash
/root/nft-manager.sh apply
```

`apply` 是直接应用并持久化。  
`safe-apply` 会先临时应用规则，如果没有执行 `confirm`，会自动回滚，适合远程 SSH 场景。

---

## 7. 交互菜单

直接运行：

```bash
/root/nft-manager.sh
```

或者：

```bash
/root/nft-manager.sh menu
```

菜单可以完成：

```text
初始化目录与默认配置
生成预览并校验
应用规则
回滚
查看状态
输出配置格式示例
安装并启用 systemd 服务
禁用并停止 systemd 服务
增加开放端口
删除开放端口
查看开放端口
增加端口转发
删除端口转发
查看端口转发
退出
```

---

## 8. 配置文件位置

初始化后会生成：

```text
/etc/nft_manager/
```

常用文件：

```text
/etc/nft_manager/settings.conf
/etc/nft_manager/allow.list
/etc/nft_manager/allow_range.list
/etc/nft_manager/allow_acl.list
/etc/nft_manager/forward.list
/etc/nft_manager/block_ip.list
/etc/nft_manager/block_port.list
/etc/nft_manager/ratelimit.list
/etc/nft_manager/connlimit.list
/etc/nft_manager/trace.list
/etc/nft_manager/rules.preview.nft
/etc/nft_manager/rules.nft
/etc/nft_manager/load_saved_rules.sh
```

备份与运行态文件：

```text
/etc/nft_manager_backups/
```

systemd 文件：

```text
/etc/systemd/system/nft-manager.service
/etc/sysctl.d/99-nft-manager.conf
```

---

## 9. settings.conf 常用配置

主配置文件：

```bash
nano /etc/nft_manager/settings.conf
```

常见配置：

```text
INPUT_POLICY=drop
FORWARD_POLICY=drop
OUTPUT_POLICY=accept

WAN_IFACE=
AUTO_OPEN_SSH_PORT=yes
SSH_PORT=22

ALLOW_PING_V4=yes
PING_V4_RATE=5/second
ALLOW_PING_V6=yes
PING_V6_RATE=5/second
ALLOW_IPV6_ND=yes

ENABLE_IPV6_FORWARD=no
WARN_IPTABLES_NAT_CONFLICT=yes
ENABLE_COUNTERS=yes
ENABLE_FORWARD_SNAT=yes

RATELIMIT_TIMEOUT=1m
FORWARD_MARK_HEX=0x20000000
FORWARD_MARK_MASK=0x20000000
```

---

## 10. SSH 端口设置

默认自动放行 SSH 端口：

```text
AUTO_OPEN_SSH_PORT=yes
SSH_PORT=22
```

如果 SSH 改成 50000：

```bash
sed -i 's/^SSH_PORT=.*/SSH_PORT=50000/' /etc/nft_manager/settings.conf
sed -i 's/^AUTO_OPEN_SSH_PORT=.*/AUTO_OPEN_SSH_PORT=yes/' /etc/nft_manager/settings.conf
```

确认：

```bash
grep -E '^(SSH_PORT|AUTO_OPEN_SSH_PORT)=' /etc/nft_manager/settings.conf
```

应用：

```bash
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
/root/nft-manager.sh safe-apply 120
```

新开一个终端确认新 SSH 端口可以登录，再执行：

```bash
/root/nft-manager.sh confirm
```

---

## 11. 设置 WAN_IFACE

端口转发需要设置外网网卡 `WAN_IFACE`。

查看默认出口网卡：

```bash
ip route show default 0.0.0.0/0
```

自动提取默认出口网卡并写入配置：

```bash
WAN_IFACE="$(ip route show default 0.0.0.0/0 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
sed -i "s/^WAN_IFACE=.*/WAN_IFACE=$WAN_IFACE/" /etc/nft_manager/settings.conf
grep '^WAN_IFACE=' /etc/nft_manager/settings.conf
```

注意：当前 GitHub 脚本没有单独的 `auto-wan` 命令，因此用上面的命令写入 `WAN_IFACE`。

---

## 12. 开放端口

### 开放 TCP 443

```bash
/root/nft-manager.sh open-add tcp 443
/root/nft-manager.sh open-list
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

### 开放 UDP 51820

```bash
/root/nft-manager.sh open-add udp 51820
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

### 同时开放 TCP 和 UDP

```bash
/root/nft-manager.sh open-add both 8443
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

### 开放端口范围

```bash
/root/nft-manager.sh open-add tcp 10000-10100
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

### 删除开放端口

```bash
/root/nft-manager.sh open-del tcp 443
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

## 13. 限制来源 IP 的开放端口

只允许指定来源访问端口：

```bash
/root/nft-manager.sh open-add tcp 22 198.51.100.10/32
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

查看：

```bash
/root/nft-manager.sh open-list
```

删除：

```bash
/root/nft-manager.sh open-del tcp 22 198.51.100.10/32
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

## 14. 端口转发

端口转发规则写入：

```text
/etc/nft_manager/forward.list
```

转发前必须设置 `WAN_IFACE`。

### 添加 IPv4 TCP 转发

把公网 `18080` 转发到内网 `192.168.1.10:8080`：

```bash
WAN_IFACE="$(ip route show default 0.0.0.0/0 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
sed -i "s/^WAN_IFACE=.*/WAN_IFACE=$WAN_IFACE/" /etc/nft_manager/settings.conf

/root/nft-manager.sh forward-add tcp 18080 192.168.1.10 8080
/root/nft-manager.sh forward-list
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

验证：

```bash
nft list table ip custom_nat
sysctl net.ipv4.ip_forward
```

正常情况下，存在 IPv4 转发规则时：

```text
net.ipv4.ip_forward = 1
```

### 删除端口转发

```bash
/root/nft-manager.sh forward-del tcp 18080 192.168.1.10 8080
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

如果没有其他 IPv4 转发规则，IPv4 forwarding 应恢复为：

```text
net.ipv4.ip_forward = 0
```

---

## 15. 限制来源 IP 的端口转发

只允许 `198.51.100.10/32` 访问公网 `18080`：

```bash
/root/nft-manager.sh forward-add tcp 18080 192.168.1.10 8080 src=198.51.100.10/32
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

删除：

```bash
/root/nft-manager.sh forward-del tcp 18080 192.168.1.10 8080 src=198.51.100.10/32
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

## 16. 黑名单 IP

编辑：

```bash
nano /etc/nft_manager/block_ip.list
```

示例：

```text
203.0.113.5
198.51.100.0/24
2001:db8::/32
```

应用：

```bash
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

黑名单会作用于：

```text
input
forward
output
```

---

## 17. 阻断端口

编辑：

```bash
nano /etc/nft_manager/block_port.list
```

示例：

```text
tcp 23
both 135-139
```

应用：

```bash
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

## 18. 限速规则

编辑：

```bash
nano /etc/nft_manager/ratelimit.list
```

示例：

```text
tcp 80 30/second burst=60
tcp 22 5/minute src=198.51.100.0/24
```

应用：

```bash
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

## 19. 连接数限制

编辑：

```bash
nano /etc/nft_manager/connlimit.list
```

示例：

```text
tcp 22 20 action=reject
tcp 443 100 mask=24
tcp 8443 30 src=198.51.100.0/24
```

应用：

```bash
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

## 20. nftrace 调试

编辑：

```bash
nano /etc/nft_manager/trace.list
```

示例：

```text
tcp 443
udp 53 src=198.51.100.0/24
```

应用：

```bash
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

## 21. 回滚

回滚到上一次已保存的运行态：

```bash
/root/nft-manager.sh rollback
```

查看状态：

```bash
/root/nft-manager.sh status
```

注意：

```text
rollback 会回滚已应用 ruleset / sysctl / loader / service
rollback 不会回滚 .list 与 settings.conf
```

如果你修改了 `.list` 文件，下一次 `preview` / `apply` 仍会按当前 `.list` 重新生成规则。

---

## 22. systemd 开机加载

### 启用

```bash
/root/nft-manager.sh enable-service
```

检查：

```bash
systemctl is-enabled nft-manager.service
systemctl is-active nft-manager.service
```

### 重启

```bash
systemctl restart nft-manager.service
systemctl is-active nft-manager.service
```

### 禁用

```bash
/root/nft-manager.sh disable-service
```

注意：

```text
disable-service 只禁用并停止 nft-manager.service
不会清空当前运行态 ruleset
```

---

## 23. 查看状态

```bash
/root/nft-manager.sh status
```

状态会显示：

```text
配置目录
规则文件
预览文件
WAN_IFACE
INPUT / FORWARD / OUTPUT policy
SSH 自动放行状态
IPv6 forwarding 状态
有效 DNAT 条数
运行态 inet custom_fw
运行态 ip custom_nat
运行态 ip6 custom_nat
service 状态
```

---

## 24. 输出配置示例

```bash
/root/nft-manager.sh sample
```

该命令会输出各类 `.list` 文件的格式说明，包括：

```text
allow.list
allow_range.list
allow_acl.list
block_ip.list
block_port.list
ratelimit.list
connlimit.list
trace.list
forward.list
```

---

## 25. 日常推荐流程

每次修改规则后固定执行：

```bash
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

如果规则错误或 SSH 断开，没有执行 `confirm`，会自动回滚。

---

## 26. 常见问题

### 端口转发不生效

检查：

```bash
grep '^WAN_IFACE=' /etc/nft_manager/settings.conf
/root/nft-manager.sh forward-list
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
nft list table ip custom_nat
sysctl net.ipv4.ip_forward
```

如果 `WAN_IFACE=` 为空，设置：

```bash
WAN_IFACE="$(ip route show default 0.0.0.0/0 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
sed -i "s/^WAN_IFACE=.*/WAN_IFACE=$WAN_IFACE/" /etc/nft_manager/settings.conf
```

### safe-apply 后忘记 confirm

等待超时后会自动回滚。

查看状态：

```bash
/root/nft-manager.sh status
```

### service 启动失败

检查：

```bash
journalctl -u nft-manager.service -n 50 --no-pager
bash -n /etc/nft_manager/load_saved_rules.sh
nft -c -f /etc/nft_manager/rules.nft
```

### 规则写错了

如果还在 `safe-apply` 未确认阶段，等待自动回滚即可。

也可以执行：

```bash
/root/nft-manager.sh rollback
```

---

## 27. 卸载

禁用 service：

```bash
/root/nft-manager.sh disable-service
```

删除脚本：

```bash
rm -f /root/nft-manager.sh
```

保留配置：

```text
/etc/nft_manager
/etc/nft_manager_backups
```

彻底删除配置：

```bash
rm -rf /etc/nft_manager
rm -rf /etc/nft_manager_backups
rm -f /etc/sysctl.d/99-nft-manager.conf
rm -f /etc/systemd/system/nft-manager.service
systemctl daemon-reload
```

彻底删除前请确认不会影响当前远程连接。

---

## 28. 文件结构

```text
/root/nft-manager.sh

/etc/nft_manager/
├── settings.conf
├── allow.list
├── allow_range.list
├── allow_acl.list
├── forward.list
├── block_ip.list
├── block_port.list
├── ratelimit.list
├── connlimit.list
├── trace.list
├── rules.preview.nft
├── rules.nft
└── load_saved_rules.sh

/etc/nft_manager_backups/
└── runtime/

/etc/systemd/system/nft-manager.service
/etc/sysctl.d/99-nft-manager.conf
```

---

## 29. 使用提醒

这是个人服务器防火墙脚本。  
修改防火墙规则前，请保留一个当前 SSH 会话，不要直接关闭终端。  
远程环境下优先使用 `safe-apply`，确认连接正常后再执行 `confirm`。
