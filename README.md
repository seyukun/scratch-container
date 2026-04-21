# usage

### Init
```bash
sudo apt install -y debian-archive-keyring iptables-persistent
if [ ! -d ${HOME}/debootstrap/rootfs ]; then
    sudo debootstrap stable rootfs http://ftp.udx.icscoe.jp/Linux/debian
    sudo chown -R $USER:$USER rootfs
fi
sudo ip link add ctrbr0 type bridge || echo "may be ok"
sudo ip addr add 10.200.1.1/24 dev ctrbr0 || echo "may be ok"
sudo ip link set ctrbr0 up || echo "may be ok"
echo net.ipv4.ip_forward=1 | sudo tee /etc/sysctl.d/10-container.conf
sudo sysctl --system
sudo iptables-save | grep -F -- '-A POSTROUTING -s 10.200.1.0/24 -o ens3 -j MASQUERADE' || \
        sudo iptables -t nat -A POSTROUTING -s 10.200.1.0/24 -o ens3 -j MASQUERADE
sudo iptables-save | grep -F -- '-A FORWARD -i ctrbr0 -j ACCEPT' || \
        sudo iptables -A FORWARD -i ctrbr0 -j ACCEPT
sudo iptables-save | grep -F -- '-A FORWARD -o ctrbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' || \
        sudo iptables -A FORWARD -o ctrbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

# boot
rootfsは各コンテナごとにコピーして実行
```bash
go build .
# usage: run <rootfs> <id> <hostname> <ip/range> <route-ip> <master-br-nic> <cpu-quota> <cpu-period> <mem-M> <cmd> [args...]
sudo ./scratch-container run ./rootfs test debian 10.200.1.2/24 10.200.1.1 ctrbr0 50000 100000 200M bash -i
```

# exec
別ターミナルから実行中のコンテナに入る
```bash
# usage: exec <id> <cmd> [args...]
sudo ./scratch-container exec test bash -i
```
