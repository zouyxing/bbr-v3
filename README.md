wget -O /root/net-tcp-tune.sh https://raw.githubusercontent.com/Jyanbai/bbr-v3/main/net-tcp-tune.sh \
  && chmod +x /root/net-tcp-tune.sh \
  && echo "alias bbr='/root/net-tcp-tune.sh'" >> ~/.bashrc \
  && source ~/.bashrc \
  && bbr
