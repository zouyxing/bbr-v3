apt update -y
apt install -y wget
wget -O /root/net-tcp-tune.sh https://raw.githubusercontent.com/zouyxing/bbr-v3/refs/heads/main/net-tcp-tune.sh
chmod +x /root/net-tcp-tune.sh
echo "alias bbr='/root/net-tcp-tune.sh'" >> ~/.bashrc
source ~/.bashrc
bbr
