#!/bin/bash
        echo ""
        echo "What IP?"
        read -p "Enter Exit Node IP-adress: " -e -i 195.181.220.142 IP
        echo ""

ssh root@$IP 'export TERM=xterm && wget https://raw.githubusercontent.com/retomoto/ovpn/master/extnd.bash && bash extnd.bash'
 echo ""
 echo ""
 echo ""
 echo ""
 echo ""
 echo ""
 echo ""
 clean
 echo "Then enter password exit node again! If you skip this step setup will not complited!"

 echo ""
 echo ""
 echo ""
 echo ""
 echo ""


scp root@$IP:/root/client.ovpn /tmp

if [[ -e /etc/openvpn/client.conf ]]; then
         rm -r /etc/openvpn/client.conf
         mv /tmp/client.ovpn /etc/openvpn/client.conf
else
        mv /tmp/client.ovpn /etc/openvpn/client.conf
fi

service openvpn restart
