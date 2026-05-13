# nft-manager.sh 使用指南

`nft-manager.sh` 是一个个人服务器用的 **Bash + nftables 防火墙管理脚本**，用于管理入站防火墙、端口开放、来源限制、黑名单、端口转发、规则预览、安全应用、自动回滚和开机自动加载。

当前 Bash 冻结基线：

```text
文件名：nft-manager.sh
SHA256：
494ddd2e37ae0b57f4af78b390452621e1e091b60fef3bfb1fdcd8a33137bd82
```

> 远程服务器修改防火墙时，固定使用 `preview -> safe-apply -> confirm`，不要直接裸 `apply`。

---

## 1. 功能概览

| 功能 | 说明 |
|---|---|
| 默认拒绝策略 | 支持 `INPUT_POLICY=drop`、`FORWARD_POLICY=drop` |
| SSH 自动放行 | 默认自动放行 `SSH_PORT`，降低锁机风险 |
| 端口开放 | 支持 `tcp`、`udp`、`both` |
| 端口范围 | 支持 `10000-10100` |
| 来源限制 | 支持 IPv4 / IPv6 CIDR |
| IP 黑名单 | 使用 nft set 管理 IPv4 / IPv6 黑名单 |
| 阻断端口 | 支持指定端口或端口范围 |
| 速率限制 | 支持 nftables dynamic set + `limit rate` |
| 连接数限制 | 支持 `ct count` |
| nftrace | 支持对指定端口开启 nftables trace |
| DNAT 转发 | 支持 IPv4 / IPv6 端口转发 |
| SNAT / masquerade | 支持转发流量自动 masquerade |
| 专属 mark | DNAT 流量使用 mark 隔离，避免误放行其他规则 |
| 规则预览 | `preview` 生成规则并自动 `nft -c` 校验 |
| 安全应用 | `safe-apply` 未确认会自动回滚 |
| 持久化 | 生成 `rules.nft`、sysctl、loader、systemd unit |
| 回滚 | 支持回滚上一轮已应用规则 |
| 并发锁 | 使用 `/run/nft_manager.lock` 避免并发写入 |
| PATH 加固 | 主脚本与 loader 固定 PATH，降低 PATH 劫持风险 |

---

## 2. 运行环境

推荐：

```text
Debian 12 / Debian 13
systemd
nftables
Bash 5.x
root 用户
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
command -v cmp
command -v date
command -v od

bash --version | head -n 1
nft --version
uname -a
```

---

## 3. 安装

把脚本放到 `/root/nft-manager.sh`：

```bash
install -m 700 nft-manager.sh /root/nft-manager.sh
```

检查语法：

```bash
bash -n /root/nft-manager.sh
```

检查 SHA256：

```bash
sha256sum /root/nft-manager.sh
```

冻结基线预期：

```text
494ddd2e37ae0b57f4af78b390452621e1e091b60fef3bfb1fdcd8a33137bd82  /root/nft-manager.sh
```

---

## 4. 初始化

```bash
/root/nft-manager.sh init
```

初始化后主要目录：

```text
/etc/nft_manager
/etc/nft_manager_backups
/etc/nft_manager_backups/runtime
/etc/nft_manager_backups/runtime/pending
```

确认权限：

```bash
stat -c '%a %n' \
  /etc/nft_manager \
  /etc/nft_manager_backups \
  /etc/nft_manager_backups/runtime \
  /etc/nft_manager_backups/runtime/pending
```

预期：

```text
700 /etc/nft_manager
700 /etc/nft_manager_backups
700 /etc/nft_manager_backups/runtime
700 /etc/nft_manager_backups/runtime/pending
```

---

## 5. 最安全的应用流程

每次修改规则后，建议固定执行：

```bash
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
/root/nft-manager.sh safe-apply 120
```

确认 SSH 没断后：

```bash
/root/nft-manager.sh confirm
```

如果没有执行 `confirm`，脚本会自动回滚到 `safe-apply` 前的运行态。

`safe-apply` 的意义：

1. 保存当前运行态 ruleset 和 sysctl。
2. 临时应用新规则。
3. 启动自动回滚倒计时。
4. 用户确认 SSH 正常后再持久化。
5. 未确认就自动恢复。

---

## 6. 常用命令

```bash
/root/nft-manager.sh init
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
/root/nft-manager.sh rollback
/root/nft-manager.sh status
/root/nft-manager.sh sample
/root/nft-manager.sh menu
```

端口开放：

```bash
/root/nft-manager.sh open-add tcp 443
/root/nft-manager.sh open-del tcp 443
/root/nft-manager.sh open-list
```

端口转发：

```bash
/root/nft-manager.sh forward-add tcp 18080 192.168.1.10 8080
/root/nft-manager.sh forward-del tcp 18080 192.168.1.10 8080
/root/nft-manager.sh forward-list
```

service：

```bash
/root/nft-manager.sh enable-service
/root/nft-manager.sh disable-service
```

---

## 7. 防火墙端口管理

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
```

### 同时开放 TCP 和 UDP

```bash
/root/nft-manager.sh open-add both 53
```

### 开放端口范围

```bash
/root/nft-manager.sh open-add tcp 10000-10100
```

### 按来源限制开放

只允许 `198.51.100.0/24` 访问 SSH：

```bash
/root/nft-manager.sh open-add tcp 22 198.51.100.0/24
```

也支持：

```bash
/root/nft-manager.sh open-add tcp 22 src=198.51.100.0/24
```

IPv6 示例：

```bash
/root/nft-manager.sh open-add tcp 443 2001:db8::/32
```

### 删除开放端口

```bash
/root/nft-manager.sh open-del tcp 443
```

删除带来源限制的规则：

```bash
/root/nft-manager.sh open-del tcp 22 198.51.100.0/24
```

---

## 8. 端口转发管理

端口转发规则写入：

```text
/etc/nft_manager/forward.list
```

脚本会生成：

```text
table ip custom_nat
table ip6 custom_nat
```

同时自动处理：

```text
net.ipv4.ip_forward
net.ipv6.conf.all.forwarding
```

### 8.1 设置 WAN_IFACE

有端口转发时，必须设置外网接口。

自动识别默认出口网卡：

```bash
WAN_IFACE="$(ip route show default 0.0.0.0/0 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
sed -i "s/^WAN_IFACE=.*/WAN_IFACE=$WAN_IFACE/" /etc/nft_manager/settings.conf
grep '^WAN_IFACE=' /etc/nft_manager/settings.conf
```

如果 `forward.list` 有有效规则，但 `WAN_IFACE` 为空，`preview` 会拒绝生成 NAT 规则。

### 8.2 IPv4 转发

把公网 TCP `18080` 转发到 `192.168.1.10:8080`：

```bash
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
/root/nft-manager.sh status
```

预期：

```text
net.ipv4.ip_forward = 1
有效 DNAT 条数: 1（IPv4=1 IPv6=0）
运行态存在表：ip custom_nat
```

### 8.3 删除转发

```bash
/root/nft-manager.sh forward-del tcp 18080 192.168.1.10 8080
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

无转发时预期：

```text
有效 DNAT 条数: 0（IPv4=0 IPv6=0）
net.ipv4.ip_forward = 0
运行态不存在表：ip custom_nat（当前无有效 IPv4 DNAT 规则，属正常状态）
```

### 8.4 端口范围转发

```bash
/root/nft-manager.sh forward-add tcp 10000-10010 192.168.1.20 10000-10010
```

要求：

```text
外部端口范围长度 = 目标端口范围长度
```

### 8.5 带来源限制的转发

```bash
/root/nft-manager.sh forward-add udp 51820 192.168.1.30 51820 src=198.51.100.0/24
```

### 8.6 IPv6 转发

```bash
/root/nft-manager.sh forward-add tcp 8443 2001:db8::10 443
/root/nft-manager.sh forward-add udp 51820 2001:db8::30 51820 src=2001:db8:100::/64
```

注意：

```text
IPv4 目标只能配 IPv4 来源限制
IPv6 目标只能配 IPv6 来源限制
```

---

## 9. 黑名单、阻断端口、限速和连接数限制

这些功能主要通过编辑 `/etc/nft_manager/*.list` 完成。编辑后统一执行：

```bash
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

### 9.1 IP 黑名单

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

效果：

| 链 | 行为 |
|---|---|
| input | 按源地址拦截 |
| output | 按目标地址拦截 |
| forward | 源地址和目标地址都拦截 |

### 9.2 阻断端口

编辑：

```bash
nano /etc/nft_manager/block_port.list
```

示例：

```text
tcp 23
both 135-139
```

### 9.3 速率限制

编辑：

```bash
nano /etc/nft_manager/ratelimit.list
```

格式：

```text
proto port_or_range rate [burst=N] [src=CIDR]
```

示例：

```text
tcp 80 30/second burst=60
tcp 22 5/minute src=198.51.100.0/24
```

### 9.4 连接数限制

编辑：

```bash
nano /etc/nft_manager/connlimit.list
```

格式：

```text
proto port_or_range limit [mask=N] [src=CIDR] [action=drop|reject]
```

示例：

```text
tcp 22 20 action=reject
tcp 443 100 mask=24
tcp 8443 30 src=198.51.100.0/24
```

### 9.5 nftrace 调试

编辑：

```bash
nano /etc/nft_manager/trace.list
```

示例：

```text
tcp 443
udp 53 src=198.51.100.0/24
```

---

## 10. systemd 开机自动加载

完成一次 `safe-apply + confirm` 后，启用 service：

```bash
/root/nft-manager.sh enable-service
```

检查：

```bash
systemctl is-enabled nft-manager.service
systemctl is-active nft-manager.service
systemctl status nft-manager.service --no-pager
```

预期：

```text
enabled
active
```

重启验证：

```bash
systemctl restart nft-manager.service
systemctl is-active nft-manager.service
```

禁用：

```bash
/root/nft-manager.sh disable-service
```

说明：

```text
disable-service 会禁用并停止 nft-manager.service
但不会清空当前运行态 ruleset
```

---

## 11. 回滚

```bash
/root/nft-manager.sh rollback
```

回滚范围：

```text
已应用 ruleset / sysctl / loader / service
```

不回滚：

```text
.list
settings.conf
```

因此，如果你添加了：

```bash
/root/nft-manager.sh open-add tcp 34567
```

并已确认持久化，之后执行 `rollback`，运行态会回滚，但 `allow.list` 里可能仍保留 `34567`。如需彻底清理：

```bash
/root/nft-manager.sh open-del tcp 34567
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

## 12. 交互菜单

进入菜单：

```bash
/root/nft-manager.sh menu
```

或直接执行：

```bash
/root/nft-manager.sh
```

菜单适合日常操作，但生产远程变更仍建议手工确认最终经过：

```text
preview -> safe-apply -> confirm
```

---

## 13. 配置文件说明

### settings.conf

路径：

```text
/etc/nft_manager/settings.conf
```

常见字段：

```conf
INPUT_POLICY=drop
FORWARD_POLICY=drop
OUTPUT_POLICY=accept

ENABLE_DROP_LOG=no
DROP_LOG_RATE=10/second

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

### allow.list

```text
tcp 22
udp 51820
both 53
```

### allow_range.list

```text
tcp 10000-10100
```

### allow_acl.list

```text
tcp 22 198.51.100.0/24
udp 53 2001:db8::/32
```

### forward.list

```text
tcp 18080 192.168.1.10 8080
udp 51820 192.168.1.30 51820 src=198.51.100.0/24
tcp 8443 2001:db8::10 443
```

---

## 14. 常见问题

### 提示 `forward.list 存在有效规则，但 settings.conf 中未设置 WAN_IFACE`

执行：

```bash
WAN_IFACE="$(ip route show default 0.0.0.0/0 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
sed -i "s/^WAN_IFACE=.*/WAN_IFACE=$WAN_IFACE/" /etc/nft_manager/settings.conf
/root/nft-manager.sh preview
```

### 提示 `端口转发参数非法`

常见原因：

```text
端口为 0
端口超过 65535
端口范围起点大于终点
外部端口范围和目标端口范围长度不一致
IPv4 目标配了 IPv6 来源限制
IPv6 目标配了 IPv4 来源限制
```

### 提示 `开放端口参数非法`

检查：

```text
协议只能是 tcp / udp / both
端口必须是 1-65535
端口范围必须 start <= end
CIDR 必须合法
```

### service 启动失败

检查：

```bash
bash -n /etc/nft_manager/load_saved_rules.sh
nft -c -f /etc/nft_manager/rules.nft
systemctl status nft-manager.service --no-pager
journalctl -u nft-manager.service -n 80 --no-pager
```

---

## 15. 最小安全基线

只保留 SSH：

```bash
cat >/etc/nft_manager/allow.list <<'EOF'
tcp 22
EOF

: >/etc/nft_manager/allow_range.list
: >/etc/nft_manager/allow_acl.list
: >/etc/nft_manager/block_ip.list
: >/etc/nft_manager/block_port.list
: >/etc/nft_manager/ratelimit.list
: >/etc/nft_manager/connlimit.list
: >/etc/nft_manager/trace.list
: >/etc/nft_manager/forward.list

chmod 600 /etc/nft_manager/*.list

/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
/root/nft-manager.sh status
```

预期：

```text
有效 DNAT 条数: 0（IPv4=0 IPv6=0）
运行态存在表：inet custom_fw
运行态不存在表：ip custom_nat（当前无有效 IPv4 DNAT 规则，属正常状态）
运行态不存在表：ip6 custom_nat（当前无有效 IPv6 DNAT 规则，属正常状态）
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
service enabled / active
```

---

## 16. 使用原则

1. 远程服务器修改规则，优先 `safe-apply + confirm`。
2. 每次应用前必须先 `preview`。
3. `nft -c` 必须通过再应用。
4. 添加转发前必须设置 `WAN_IFACE`。
5. 回滚不回滚 `.list` 和 `settings.conf`，需要自己清理配置意图。
6. 冻结基线不继续加功能；新功能应另开版本。
