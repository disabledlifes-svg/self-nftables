chatgpt plus搓的

任何改动记得先选项2预览一遍没问题再选项3应用一遍


sudo wget -O nft-manager.sh \
https://raw.githubusercontent.com/disabledlifes-svg/self-nftables/refs/heads/main/nft-manager.sh && chmod +x /root/nft-manager.sh && ./nft-manager.sh

进入脚本后先操作选项1,2,3


开启端口转发功能前提

WAN_IFACE="$(ip route show default 0.0.0.0/0 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"

[ -n "$WAN_IFACE" ] || { echo "未找到默认出口网卡"; exit 1; }

sed -i "s/^WAN_IFACE=.*/WAN_IFACE=$WAN_IFACE/" /etc/nft_manager/settings.conf

grep '^WAN_IFACE=' /etc/nft_manager/settings.conf


nft-manager.service管理

systemctl daemon-reload

systemctl enable nft-manager.service

systemctl restart nft-manager.service

systemctl status nft-manager.service


常用的命令

sudo /root/nft-manager.sh status

sudo /root/nft-manager.sh open-list

sudo /root/nft-manager.sh forward-list

sudo /root/nft-manager.sh preview

sudo nft -c -f /etc/nft_manager/rules.preview.nft

sudo /root/nft-manager.sh apply

sudo /root/nft-manager.sh rollback

sudo systemctl status nft-manager.service --no-pager


紧急恢复

sudo /root/nft-manager.sh rollback


完全清空运行态规则

sudo nft flush ruleset
