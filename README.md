chatgpt plus搓的

chmod +x /root/nft-manager.sh

bash /root/nft-manager.sh

systemctl daemon-reload
systemctl enable nft-manager.service
systemctl restart nft-manager.service
systemctl status nft-manager.service

常用的命令
sudo /root/nft-manager status
sudo /root/nft-manager open-list
sudo /root/nft-manager forward-list
sudo /root/nft-manager preview
sudo nft -c -f /etc/nft_manager/rules.preview.nft
sudo /root/nft-manager apply
sudo /root/nft-manager rollback
sudo systemctl status nft-manager.service --no-pager

紧急恢复
sudo /root/nft-manager rollback

完全清空运行态规则
sudo nft flush ruleset
