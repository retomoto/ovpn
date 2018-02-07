#!/bin/bash
# SRV1 start

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -qs "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 2
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "The TUN device is not available
You need to enable TUN before running this script"
	exit 3
fi

if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported"
	exit 4
fi
if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Looks like you aren't running this installer on Debian, Ubuntu or CentOS"
	exit 5
fi

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (lowendspirit.com)
# and to avoid getting an IPv6.
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -4qO- "http://whatismyip.akamai.com/")
fi

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "Looks like OpenVPN is already installed"
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a new user"
		echo "   2) Revoke an existing user"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Select an option [1-4]: " option
		case $option in
			1) 
			echo ""
			echo "Tell me a name for the client certificate"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/
			./easyrsa build-client-full $CLIENT nopass
			# Generates the custom client.ovpn
			newclient "$CLIENT"
			echo ""
			echo "Client $CLIENT added, configuration is available at" ~/"$CLIENT.ovpn"
			exit
			;;
			2)
			# This option could be documented a bit better and maybe even be simplimplified
			# ...but what can I say, I want some sleep too
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit 6
			fi
			echo ""
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Select one client [1]: " CLIENTNUMBER
			else
				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke $CLIENT
			EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
			rm -rf pki/reqs/$CLIENT.req
			rm -rf pki/private/$CLIENT.key
			rm -rf pki/issued/$CLIENT.crt
			rm -rf /etc/openvpn/crl.pem
			cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
			# CRL is read with each client connection, when OpenVPN is dropped to nobody
			chown nobody:$GROUPNAME /etc/openvpn/crl.pem
			echo ""
			echo "Certificate for client $CLIENT revoked"
			exit
			;;
			3) 
			echo ""
			read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					#IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.0.1.0/24 '"'"'!'"'"' -d 10.0.1.0/24 -j SNAT --to ' | cut -d " " -f 10)
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					#firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					#firewall-cmd --zone=trusted --remove-source=10.0.1.0/24
					#firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					#firewall-cmd --permanent --zone=trusted --remove-source=10.0.1.0/24
					ls
				else
					#IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.0.1.0/24 ! -d 10.0.1.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
					if iptables -L -n | grep -qE '^ACCEPT'; then
						#iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
						#iptables -D FORWARD -s 10.0.1.0/24 -j ACCEPT
						#iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						#sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
						#sed -i "/iptables -I FORWARD -s 10.0.1.0\/24 -j ACCEPT/d" $RCLOCAL
						#sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
						ls
					fi
				fi
				if hash sestatus 2>/dev/null; then
					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
						if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
							semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
						fi
					fi
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				echo ""
				echo "OpenVPN removed!"
			else
				echo ""
				echo "Removal aborted!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo 'Welcome to this quick OpenVPN "road warrior" installer'
	echo ""
	# OpenVPN setup and first user creation
	echo "First I need to know the IPv4 address of the network interface you want OpenVPN"
	echo "listening to."
	read -p "IP address: " -e -i $IP IP
	echo ""
	echo "Which protocol do you want for OpenVPN connections?"
	echo "   1) UDP"
	echo "   2) TCP (recommended)"
	read -p "Protocol [1-2]: " -e -i 2 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
	echo ""
	echo "What port do you want OpenVPN listening to?"
	read -p "Port: " -e -i 80 PORT
	echo ""
	echo "Finally, tell me your name for the client certificate"
	echo "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Else, the distro is CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl wget ca-certificates -y
	fi
	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	
	# Get easy-rsa
	wget -O ~/EasyRSA-3.0.4.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz"
	tar xzf ~/EasyRSA-3.0.4.tgz -C ~/
	mv ~/EasyRSA-3.0.4/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.4/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.4.tgz
	cd /etc/openvpn/easy-rsa/
	# Create the PKI, set up the CA, the DH params and the server + client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
	# CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	# Generate key for tls-auth
	openvpn --genkey --secret /etc/openvpn/ta.key
	
	
	# Generate server.conf
	echo "local $IP
port $PORT
proto $PROTOCOL
dev tun1
sndbuf 0
rcvbuf 0
push \"sndbuf 393216\"
push \"rcvbuf 393216\"
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
auth SHA512
;topology subnet
server 10.0.1.0 255.255.255.0
push \"redirect-gateway def1 bypass-dhcp\"
push \"dhcp-option DNS 8.8.8.8\"
push \"dhcp-option DNS 8.8.4.4\"
keepalive 10 120
cipher AES-256-CBC
comp-lzo
max-clients 5
;user nobody
;group $GROUPNAME
persist-key
persist-tun
status /var/log/ovpnsrv-status.log
log /var/log/ovpnsrv.log
verb 4
block-outside-dns
mute 20" >> /etc/openvpn/server.conf


	# Enable net.ipv4.ip_forward for the system
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		#firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		#firewall-cmd --zone=trusted --add-source=10.0.1.0/24
		#firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		#firewall-cmd --permanent --zone=trusted --add-source=10.0.1.0/24
		ls
	else
		# Needed to use rc.local with some systemd distros
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL
		#sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.0.1.0/24 ! -d 10.0.1.0/24 -j SNAT --to $IP" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# If iptables has at least one REJECT rule, we asume this is needed.
			# Not the best approach but I can't think of other and this shouldn't
			# cause problems.
			#iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			#iptables -I FORWARD -s 10.0.1.0/24 -j ACCEPT
			#iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			#sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			#sed -i "1 a\iptables -I FORWARD -s 10.0.1.0/24 -j ACCEPT" $RCLOCAL
			#sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
			ls
		fi
	fi
	# If SELinux is enabled and a custom port or TCP was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
				# semanage isn't available in CentOS 6 by default
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
			fi
		fi
	fi

	# Try to detect a NATed connection and ask about it to potential LowEndSpirit users
	EXTERNALIP=$(wget -4qO- "http://whatismyip.akamai.com/")
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (e.g. LowEndSpirit), I need to know the external IP"
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	# client-common.txt is created so we have a template to add further users later
	echo "
client
dev tun
remote $IP
port $PORT
proto $PROTOCOL
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
comp-lzo
verb 3
;tls-client
;remote-cert-tls server
key-direction 1
#setenv opt block-outside-dns" > /etc/openvpn/client-common.txt
	# Generates the custom client.ovpn
	newclient "$CLIENT"
	echo ""
	echo "Finished!"
	echo ""
	echo "Your client configuration is available at" ~/"$CLIENT.ovpn"
	echo "If you want to add more clients, you simply need to run this script again!"
	
	
	sleep 3
clear

	echo "Warning! Next step! Enter Remote IP and Password"
	
sleep 3	
#!/bin/bash
        echo ""
        echo "What IP?"
        read -p "Enter Exit Node IP-adress: " -e -i 195.181.220.142 IP2
        echo ""

ssh root@$IP2 'export TERM=xterm && wget https://raw.githubusercontent.com/retomoto/ovpn/master/extnd.bash && bash extnd.bash'

 clear
 echo "Then enter password exit node again! If you skip this step setup will not complited!"


scp root@$IP2:/root/client.ovpn /tmp

if [[ -e /etc/openvpn/client.conf ]]; then
         rm -r /etc/openvpn/client.conf
         mv /tmp/client.ovpn /etc/openvpn/client.conf
else
        mv /tmp/client.ovpn /etc/openvpn/client.conf
fi

service openvpn restart

#Generate up_s2s.sh
	echo "#!/bin/bash
	
#!/bin/sh

# A Sample OpenVPN-aware firewall.

# eth0 is connected to the internet.

# Loopback address
LOOP=127.0.0.1

# Delete old iptables rules
# and temporarily block all traffic.
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -F

# Set default policies
iptables -P OUTPUT ACCEPT
iptables -P INPUT DROP
iptables -P FORWARD DROP

# Prevent external packets from using loopback addr
iptables -A INPUT -i eth0 -s $LOOP -j DROP
iptables -A FORWARD -i eth0 -s $LOOP -j DROP
iptables -A INPUT -i eth0 -d $LOOP -j DROP
iptables -A FORWARD -i eth0 -d $LOOP -j DROP

# Anything coming from the Internet should have a real Internet address
iptables -A FORWARD -i eth0 -s 192.168.0.0/16 -j DROP
iptables -A FORWARD -i eth0 -s 172.16.0.0/12 -j DROP
iptables -A FORWARD -i eth0 -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 192.168.0.0/16 -j DROP
iptables -A INPUT -i eth0 -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP

# Block outgoing NetBios 
iptables -A FORWARD -p tcp --sport 137:139 -o eth0 -j DROP
iptables -A FORWARD -p udp --sport 137:139 -o eth0 -j DROP
iptables -A OUTPUT -p tcp --sport 137:139 -o eth0 -j DROP
iptables -A OUTPUT -p udp --sport 137:139 -o eth0 -j DROP

# Allow local loopback
iptables -A INPUT -s $LOOP -j ACCEPT
iptables -A INPUT -d $LOOP -j ACCEPT

# Allow incoming pings (can be disabled)
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Allow services such as www and ssh (can be disabled)
iptables -A INPUT -p tcp --dport ssh -j ACCEPT

# Allow OpenVPN 
iptables -A INPUT -p $PROTOCOL --dport $PORT -j ACCEPT

iptables -A INPUT -i tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -j ACCEPT
iptables -A INPUT -i tap+ -j ACCEPT
iptables -A FORWARD -i tap+ -j ACCEPT

# Keep state of connections from local machine and private subnets
iptables -A OUTPUT -m state --state NEW -o eth0 -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state NEW -o eth0 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT	
	
sleep 10
/sbin/ip route add default via 10.0.2.1 dev tun0 table 10
/sbin/ip rule add from 10.0.1.0/24 lookup 10 pref 10" >> /etc/openvpn/up_s2s.sh
#add chmod
chmod +x /etc/openvpn/up_s2s.sh

fi
	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	
clear

cat ~/$CLIENT.ovpn