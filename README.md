# nft-manager

> 一个面向远程 Linux 服务器的 **Bash + nftables 防火墙与端口转发管理脚本**。  
> 核心目标是：**规则清晰、应用安全、失败可回滚、适合 SSH 远程维护**。

```text
冻结基线：final clean structured frozen + PATH hardening
SHA256：494ddd2e37ae0b57f4af78b390452621e1e091b60fef3bfb1fdcd8a33137bd82
```

---

## 目录

- [它能做什么](#它能做什么)
- [适用场景](#适用场景)
- [安全模型](#安全模型)
- [安装与校验](#安装与校验)
- [第一次使用](#第一次使用)
- [推荐工作流](#推荐工作流)
- [配置文件总览](#配置文件总览)
- [防火墙规则使用](#防火墙规则使用)
- [端口转发使用](#端口转发使用)
- [safe-apply 与回滚机制](#safe-apply-与回滚机制)
- [systemd 服务](#systemd-服务)
- [常见问题](#常见问题)
- [维护建议](#维护建议)

---

## 它能做什么

`nft-manager.sh` 用一组简单的 `.list` 文件描述防火墙规则，然后生成 nftables ruleset。

它不是 nftables 的替代品，而是一个更安全、更固定、更适合日常维护的规则管理包装器。

### 防火墙能力

| 功能 | 说明 |
|---|---|
| 默认策略 | 支持 `INPUT / FORWARD / OUTPUT` policy |
| SSH 兜底放行 | 避免远程服务器误锁 SSH |
| 开放端口 | 支持 TCP、UDP、TCP+UDP |
| 端口范围 | 支持 `10000-10100` 形式 |
| 来源限制 | 支持 IPv4 / IPv6 / CIDR |
| IP 黑名单 | 使用 nftables set 收敛 |
| 端口拦截 | 支持单端口和范围 |
| 速率限制 | 基于 dynamic set 和 `limit rate over` |
| 连接数限制 | 基于 `ct count over` |
| trace 调试 | 支持 `meta nftrace set 1` |
| 预校验 | 所有规则应用前先执行 `nft -c` |
| 安全应用 | `safe-apply` 未确认会自动回滚 |

### 端口转发能力

| 功能 | 说明 |
|---|---|
| IPv4 DNAT | 支持公网端口转发到 IPv4 目标 |
| IPv6 DNAT | 支持公网端口转发到 IPv6 目标 |
| 单端口转发 | 如 `18080 -> 192.168.1.10:8080` |
| 范围转发 | 外部端口范围与目标端口范围一一映射 |
| 来源限制 | 支持 `src=CIDR` |
| 自动 sysctl | 有 DNAT 时自动启用对应 forwarding |
| MASQUERADE | 可为脚本管理的转发连接做 SNAT |
| 连接标记 | 使用 `ct mark` 避免误放行其他管理器的 DNAT 流量 |

---

## 适用场景

适合：

- 单台 VPS / 云服务器的防火墙管理
- 需要远程 SSH 安全维护的服务器
- 简单端口开放、封禁、限速、端口转发
- 希望避免手写大量 nftables 命令
- 希望有 `safe-apply` 自动回滚机制

不适合：

- 超大规模黑名单，例如几十万条 IP
- 多租户 Web 控制面板
- 复杂企业网络策略编排
- 需要数据库、API、多用户权限模型的场景

---

## 安全模型

脚本遵循几个原则：

1. **不直接把用户输入拼成 shell 命令执行。**  
   `.list` 输入会先经过格式校验，再生成 rules file，最后由 `nft -c -f` 进行官方语法校验。

2. **远程服务器优先使用 `safe-apply`。**  
   如果规则导致 SSH 断开，未执行 `confirm` 时会自动恢复到应用前运行态。

3. **托管文件权限严格。**  
   配置目录默认 `700`，规则文件默认 `600`。

4. **只管理自己的表。**  
   默认托管表为：

   ```text
   inet custom_fw
   ip   custom_nat
   ip6  custom_nat
   ```

5. **PATH 已固定。**  
   主脚本和 systemd loader 都会锁定 PATH，降低异常执行环境中的 PATH 劫持风险。

---

## 安装与校验

### 下载

```bash
cd /root

wget -O nft-manager.sh \
  'https://raw.githubusercontent.com/disabledlifes-svg/self-nftables/main/nft-manager.sh'

chmod 700 /root/nft-manager.sh
```

### 语法检查

```bash
bash -n /root/nft-manager.sh
```

### SHA256 校验

```bash
sha256sum /root/nft-manager.sh
```

预期：

```text
494ddd2e37ae0b57f4af78b390452621e1e091b60fef3bfb1fdcd8a33137bd82  /root/nft-manager.sh
```

---

## 第一次使用

初始化配置目录：

```bash
/root/nft-manager.sh init
```

初始化后会创建：

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

正常应为：

```text
700 /etc/nft_manager
700 /etc/nft_manager_backups
700 /etc/nft_manager_backups/runtime
700 /etc/nft_manager_backups/runtime/pending
```

---

## 推荐工作流

远程服务器建议始终按这个顺序操作：

```bash
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft

/root/nft-manager.sh safe-apply 120
```

确认 SSH 没断开后：

```bash
/root/nft-manager.sh confirm
```

如果没有执行 `confirm`，脚本会自动回滚。

---

## 配置文件总览

所有主要配置都在：

```text
/etc/nft_manager
```

| 文件 | 作用 |
|---|---|
| `settings.conf` | 全局设置 |
| `allow.list` | 开放单端口 |
| `allow_range.list` | 开放端口范围 |
| `allow_acl.list` | 按来源开放端口 |
| `block_ip.list` | 按 IP / CIDR 拦截 |
| `block_port.list` | 按端口拦截 |
| `ratelimit.list` | 速率限制 |
| `connlimit.list` | 新建连接数限制 |
| `trace.list` | nft trace 调试 |
| `forward.list` | 端口转发 / DNAT |

查看内置示例：

```bash
/root/nft-manager.sh sample
```

---

## 防火墙规则使用

### 1. 全局策略

编辑：

```bash
nano /etc/nft_manager/settings.conf
```

常用字段：

```ini
INPUT_POLICY=drop
FORWARD_POLICY=drop
OUTPUT_POLICY=accept

AUTO_OPEN_SSH_PORT=yes
SSH_PORT=22

ALLOW_PING_V4=yes
PING_V4_RATE=5/second
ALLOW_PING_V6=yes
PING_V6_RATE=5/second
ALLOW_IPV6_ND=yes

ENABLE_COUNTERS=yes
ENABLE_DROP_LOG=no
DROP_LOG_RATE=10/second
```

建议远程服务器保留：

```ini
AUTO_OPEN_SSH_PORT=yes
```

如果你的 SSH 不是 22 端口，必须同步修改：

```bash
sed -i 's/^SSH_PORT=.*/SSH_PORT=你的SSH端口/' /etc/nft_manager/settings.conf
```

---

### 2. 开放端口

#### 使用命令添加

开放 TCP 80：

```bash
/root/nft-manager.sh open-add tcp 80
```

开放 UDP 53：

```bash
/root/nft-manager.sh open-add udp 53
```

TCP 和 UDP 都开放：

```bash
/root/nft-manager.sh open-add both 443
```

开放端口范围：

```bash
/root/nft-manager.sh open-add tcp 10000-10100
```

查看：

```bash
/root/nft-manager.sh open-list
```

删除：

```bash
/root/nft-manager.sh open-del tcp 80
```

#### 直接编辑 allow.list

```bash
nano /etc/nft_manager/allow.list
```

格式：

```text
proto port
```

示例：

```text
tcp 22
tcp 80
udp 53
both 443
```

#### 直接编辑 allow_range.list

```bash
nano /etc/nft_manager/allow_range.list
```

格式：

```text
proto start-end
```

示例：

```text
tcp 10000-10100
udp 20000-20100
both 30000-30100
```

---

### 3. 按来源开放端口

如果只允许某个来源访问某个端口，使用 `allow_acl.list`。

```bash
nano /etc/nft_manager/allow_acl.list
```

格式：

```text
proto port_or_range src_cidr
```

示例：

```text
tcp 22 198.51.100.0/24
tcp 443 203.0.113.5
udp 53 2001:db8::/32
```

也可以用命令添加：

```bash
/root/nft-manager.sh open-add tcp 22 198.51.100.0/24
/root/nft-manager.sh open-add udp 53 src=2001:db8::/32
```

#### SSH 只允许特定来源时的注意事项

如果你写了：

```text
tcp 22 198.51.100.0/24
```

但 `settings.conf` 里仍然是：

```ini
AUTO_OPEN_SSH_PORT=yes
```

脚本仍会额外生成 SSH 兜底放行规则。

如果你确实要让 SSH 只允许特定来源，请设置：

```ini
AUTO_OPEN_SSH_PORT=no
```

然后使用 `safe-apply`，确认不会锁死 SSH。

---

### 4. 拦截 IP / CIDR

编辑：

```bash
nano /etc/nft_manager/block_ip.list
```

格式：每行一个 IP 或 CIDR。

示例：

```text
203.0.113.5
198.51.100.0/24
2001:db8::/32
```

拦截范围：

| 链 | 行为 |
|---|---|
| input | 按源地址拦截 |
| output | 按目标地址拦截 |
| forward | 同时按源地址和目标地址拦截 |

脚本会生成 nftables set，而不是为每个 IP 生成一条独立 rule。

---

### 5. 拦截端口

编辑：

```bash
nano /etc/nft_manager/block_port.list
```

格式：

```text
proto port_or_range
```

示例：

```text
tcp 23
both 135-139
udp 1900
```

---

### 6. 速率限制

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
tcp 22 5/minute
udp 53 100/second src=198.51.100.0/24
```

说明：

- 只匹配 `ct state new`
- 使用 nftables dynamic set
- 按来源地址记录
- 超过速率后 `drop`

全局 timeout 在 `settings.conf` 中设置：

```ini
RATELIMIT_TIMEOUT=1m
```

---

### 7. 连接数限制

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

说明：

- 使用 `ct count over`
- 默认动作为 `drop`
- TCP 可使用 `action=reject`，会生成 `reject with tcp reset`
- `mask=N` 仅稳定支持 IPv4
- IPv6 聚合建议使用 `src=IPv6前缀`

---

### 8. trace 调试

编辑：

```bash
nano /etc/nft_manager/trace.list
```

格式：

```text
proto port_or_range [src=CIDR]
```

示例：

```text
tcp 443
udp 53 src=198.51.100.0/24
```

会生成：

```nft
meta nftrace set 1
```

用于 nftables trace 调试。

---

## 端口转发使用

端口转发配置文件是：

```text
/etc/nft_manager/forward.list
```

启用转发前，必须设置公网网卡：

```ini
WAN_IFACE=eth0
```

---

### 1. 设置 WAN_IFACE

查看默认路由：

```bash
ip route
```

示例：

```text
default via 104.168.102.1 dev eth0
```

其中 `eth0` 就是 `WAN_IFACE`：

```bash
sed -i 's/^WAN_IFACE=.*/WAN_IFACE=eth0/' /etc/nft_manager/settings.conf
```

自动提取默认出口网卡：

```bash
WAN_IFACE="$(ip route show default 0.0.0.0/0 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"

[ -n "$WAN_IFACE" ] || { echo "未找到默认出口网卡"; exit 1; }

sed -i "s/^WAN_IFACE=.*/WAN_IFACE=$WAN_IFACE/" /etc/nft_manager/settings.conf
grep '^WAN_IFACE=' /etc/nft_manager/settings.conf
```

---

### 2. IPv4 单端口转发

把公网 TCP `18080` 转发到内网 `192.168.1.10:8080`：

```bash
/root/nft-manager.sh forward-add tcp 18080 192.168.1.10 8080
```

查看：

```bash
/root/nft-manager.sh forward-list
```

预览并应用：

```bash
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft

/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

查看运行态 NAT 表：

```bash
nft list table ip custom_nat
```

---

### 3. UDP 端口转发

例如 WireGuard：

```bash
/root/nft-manager.sh forward-add udp 51820 192.168.1.30 51820
```

---

### 4. 外部端口与目标端口相同

如果省略目标端口，默认目标端口等于外部端口：

```bash
/root/nft-manager.sh forward-add tcp 443 192.168.1.10
```

等价于：

```bash
/root/nft-manager.sh forward-add tcp 443 192.168.1.10 443
```

---

### 5. 端口范围转发

外部端口范围和目标端口范围长度必须一致。

```bash
/root/nft-manager.sh forward-add tcp 10000-10010 192.168.1.20 10000-10010
```

不允许长度不一致：

```bash
/root/nft-manager.sh forward-add tcp 10000-10010 192.168.1.20 20000-20020
```

---

### 6. 按来源限制转发

只允许 `198.51.100.0/24` 访问公网 UDP 51820：

```bash
/root/nft-manager.sh forward-add udp 51820 192.168.1.30 51820 src=198.51.100.0/24
```

IPv6 示例：

```bash
/root/nft-manager.sh forward-add tcp 8443 2001:db8::10 443 src=2001:db8:100::/64
```

注意：

- IPv4 目标只能搭配 IPv4 `src`
- IPv6 目标只能搭配 IPv6 `src`
- 混用会被拒绝

---

### 7. 删除端口转发

```bash
/root/nft-manager.sh forward-del tcp 18080 192.168.1.10 8080
```

删除后重新应用：

```bash
/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

### 8. 直接编辑 forward.list

```bash
nano /etc/nft_manager/forward.list
```

格式：

```text
proto ext_port_or_range target_ip [target_port_or_range] [src=CIDR]
```

示例：

```text
tcp 443 192.168.1.10 443
tcp 10000-10010 192.168.1.20 10000-10010
udp 51820 192.168.1.30 51820 src=198.51.100.0/24
tcp 8443 2001:db8::10 443
udp 51820 2001:db8::30 51820 src=2001:db8:100::/64
```

---

### 9. 转发相关配置

`settings.conf` 中与转发相关的字段：

```ini
WAN_IFACE=eth0
ENABLE_FORWARD_SNAT=yes
ENABLE_IPV6_FORWARD=no
FORWARD_MARK_HEX=0x20000000
FORWARD_MARK_MASK=0x20000000
```

| 字段 | 说明 |
|---|---|
| `WAN_IFACE` | 公网入口 / 出口网卡，端口转发必填 |
| `ENABLE_FORWARD_SNAT` | 是否对脚本管理的转发连接执行 masquerade |
| `ENABLE_IPV6_FORWARD` | 无 IPv6 DNAT 时是否仍启用 IPv6 forwarding |
| `FORWARD_MARK_HEX` | 转发连接标记值 |
| `FORWARD_MARK_MASK` | 转发连接标记掩码 |

普通使用不建议修改 `FORWARD_MARK_HEX` 和 `FORWARD_MARK_MASK`。

---

## safe-apply 与回滚机制

### 为什么推荐 safe-apply

远程服务器最怕规则写错导致 SSH 断开。  
`safe-apply` 的流程是：

1. 生成规则
2. `nft -c` 校验
3. 保存当前运行态快照
4. 临时应用新规则
5. 启动自动回滚计时器
6. 用户确认 SSH 正常后执行 `confirm`
7. 未确认则自动恢复旧运行态

### 使用

```bash
/root/nft-manager.sh safe-apply 120
```

确认：

```bash
/root/nft-manager.sh confirm
```

不确认则自动回滚。

### 手动回滚

```bash
/root/nft-manager.sh rollback
```

注意：

`rollback` 不回滚 `.list` 与 `settings.conf`。  
如果配置文件没改回来，下次 `preview/apply` 仍会按当前配置重新生成。

---

## systemd 服务

启用开机加载：

```bash
/root/nft-manager.sh enable-service
```

检查：

```bash
systemctl is-enabled nft-manager.service
systemctl is-active nft-manager.service
systemctl status nft-manager.service --no-pager
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

注意：

`disable-service` 不会清空当前运行态 ruleset。

---

## 常见问题

### forward.list 有规则，但提示 WAN_IFACE 未设置

错误：

```text
forward.list 存在有效规则，但 settings.conf 中未设置 WAN_IFACE。
```

原因：端口转发必须知道公网网卡。

解决：

```bash
WAN_IFACE="$(ip route show default 0.0.0.0/0 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
sed -i "s/^WAN_IFACE=.*/WAN_IFACE=$WAN_IFACE/" /etc/nft_manager/settings.conf

/root/nft-manager.sh preview
```

---

### 不需要端口转发，如何关闭 NAT

清空 `forward.list`：

```bash
: > /etc/nft_manager/forward.list
chmod 600 /etc/nft_manager/forward.list

/root/nft-manager.sh preview
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

### 如何避免 SSH 被锁死

远程服务器不要直接上来就执行：

```bash
/root/nft-manager.sh apply
```

推荐：

```bash
/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

---

### forward-list 显示很宽

`forward-list` 为兼容 IPv6 和较长 CIDR，使用固定宽度表格。  
在手机或窄终端中可能显示较宽，但不影响规则功能。

也可以直接查看：

```bash
cat -n /etc/nft_manager/forward.list
```

---

### 如何查看当前实际规则

```bash
nft list table inet custom_fw
nft list table ip custom_nat
nft list table ip6 custom_nat
```

---

## 维护建议

### 修改规则后推荐流程

```bash
/root/nft-manager.sh preview
nft -c -f /etc/nft_manager/rules.preview.nft

/root/nft-manager.sh safe-apply 120
/root/nft-manager.sh confirm
```

### 更新 GitHub 文件后校验

```bash
curl -L 'https://raw.githubusercontent.com/disabledlifes-svg/self-nftables/main/nft-manager.sh' -o /tmp/nft-manager.github.sh
sha256sum /tmp/nft-manager.github.sh
```

预期：

```text
494ddd2e37ae0b57f4af78b390452621e1e091b60fef3bfb1fdcd8a33137bd82  /tmp/nft-manager.github.sh
```

### 大规则集提醒

此脚本适合中小规模规则管理。  
如果黑名单达到几万或几十万条，建议设计专门的 nft set include 文件或独立 set 加载流程，而不是每次全量重生成。

---

## 卸载或清理

禁用服务：

```bash
/root/nft-manager.sh disable-service
```

手动删除托管表：

```bash
nft delete table inet custom_fw 2>/dev/null || true
nft delete table ip custom_nat 2>/dev/null || true
nft delete table ip6 custom_nat 2>/dev/null || true
```

如果要删除配置：

```bash
rm -rf /etc/nft_manager
rm -rf /etc/nft_manager_backups
rm -f /etc/sysctl.d/99-nft-manager.conf
rm -f /etc/systemd/system/nft-manager.service
systemctl daemon-reload
```

执行删除前请确认不会影响现有网络连接。

---

## 许可证

请根据你的仓库需要添加许可证文件，例如：

- MIT
- Apache-2.0
- GPL-3.0
