#!/bin/bash

red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'
_red() { echo -e ${red}$*${none}; }
_green() { echo -e ${green}$*${none}; }
_yellow() { echo -e ${yellow}$*${none}; }
_magenta() { echo -e ${magenta}$*${none}; }
_cyan() { echo -e ${cyan}$*${none}; }

# Root
[[ $(id -u) != 0 ]] && echo -e "\n Oops...Please run as ${red}root ${none}user ${yellow}~(^_^) ${none}\n" && exit 1

cmd="apt-get"

sys_bit=$(uname -m)

case $sys_bit in
# i[36]86)
# 	v2ray_bit="32"
# 	caddy_arch="386"
# 	;;
'amd64' | x86_64)
	v2ray_bit="64"
	caddy_arch="amd64"
	;;
# *armv6*)
# 	v2ray_bit="arm32-v6"
# 	caddy_arch="arm6"
# 	;;
# *armv7*)
# 	v2ray_bit="arm32-v7a"
# 	caddy_arch="arm7"
# 	;;
*aarch64* | *armv8*)
	v2ray_bit="arm64-v8a"
	caddy_arch="arm64"
	;;
*)
	echo -e "
	Oh no...This ${red}lousy script${none} does not support your system. ${yellow}(-_-) ${none}

	Note: Only supports Ubuntu 16+ / Debian 8+ / CentOS 7+ systems
	" && exit 1
	;;
esac

# Stupid detection method
if [[ $(command -v apt-get) || $(command -v yum) ]] && [[ $(command -v systemctl) ]]; then

	if [[ $(command -v yum) ]]; then

		cmd="yum"

	fi

else

	echo -e "
	Oh no...This ${red}lousy script${none} does not support your system. ${yellow}(-_-) ${none}

	Note: Only supports Ubuntu 16+ / Debian 8+ / CentOS 7+ systems
	" && exit 1

fi

uuid=$(cat /proc/sys/kernel/random/uuid)
old_id="e55c8d17-2cf3-b21a-bcf1-eeacb011ed79"
v2ray_server_config="/etc/v2ray/config.json"
v2ray_client_config="/etc/v2ray/233blog_v2ray_config.json"
backup="/etc/v2ray/233blog_v2ray_backup.conf"
_v2ray_sh="/usr/local/sbin/v2ray"
systemd=true
# _test=true

transport=(
	TCP
	TCP_HTTP
	WebSocket
	"WebSocket + TLS"
	HTTP/2
	mKCP
	mKCP_utp
	mKCP_srtp
	mKCP_wechat-video
	mKCP_dtls
	mKCP_wireguard
	QUIC
	QUIC_utp
	QUIC_srtp
	QUIC_wechat-video
	QUIC_dtls
	QUIC_wireguard
	TCP_dynamicPort
	TCP_HTTP_dynamicPort
	WebSocket_dynamicPort
	mKCP_dynamicPort
	mKCP_utp_dynamicPort
	mKCP_srtp_dynamicPort
	mKCP_wechat-video_dynamicPort
	mKCP_dtls_dynamicPort
	mKCP_wireguard_dynamicPort
	QUIC_dynamicPort
	QUIC_utp_dynamicPort
	QUIC_srtp_dynamicPort
	QUIC_wechat-video_dynamicPort
	QUIC_dtls_dynamicPort
	QUIC_wireguard_dynamicPort
	VLESS_WebSocket_TLS
)

ciphers=(
	aes-128-gcm
	aes-256-gcm
	chacha20-ietf-poly1305
)

_load() {
	local _dir="/etc/v2ray/233boy/v2ray/src/"
	. "${_dir}$@"
}
_sys_timezone() {
	IS_OPENVZ=
	if hostnamectl status | grep -q openvz; then
		IS_OPENVZ=1
	fi

	echo
	timedatectl set-timezone Asia/Shanghai
	timedatectl set-ntp true
	echo "The time zone of your host has been set to Asia/Shanghai and the time has been automatically synchronized through systemd-timesyncd."
	echo

	if [[ $IS_OPENVZ ]]; then
		echo
		echo -e "Your host environment is ${yellow}Openvz${none}, it is recommended to use ${yellow}v2ray mkcp${none} series protocols."
		echo -e "Note: ${yellow}Openvz${none} system time cannot be synchronized by virtual machine internal programs."
		echo -e "If the host time is ${yellow}more than 90 seconds${none} away from the actual time, v2ray will not be able to communicate normally. Please send a ticket to contact the vps host to adjust."
	fi
}

_sys_time() {
	echo -e "\nHost time: ${yellow}"
	timedatectl status | sed -n '1p;4p'
	echo -e "${none}"
	[[ $IS_OPENV ]] && pause
}
v2ray_config() {
	# clear
	echo
	while :; do
		echo -e "Please select the "$yellow"V2Ray"$none" transport protocol [${magenta}1-${#transport[*]}$none]"
		echo
		for ((i = 1; i <= ${#transport[*]}; i++)); do
			Stream="${transport[$i - 1]}"
			if [[ "$i" -le 9 ]]; then
				# echo
				echo -e "$yellow  $i. $none${Stream}"
			else
				# echo
				echo -e "$yellow $i. $none${Stream}"
			fi
		done
		echo
		echo "Note 1: [dynamicPort] means that dynamic ports are enabled."
		echo "Note 2: [utp | srtp | wechat-video | dtls | wireguard] respectively disguise as [BT download | video call | WeChat video call | DTLS 1.2 data packet | WireGuard data packet]"
		echo
		read -p "$(echo -e "(Default protocol: ${cyan}TCP$none)"):" v2ray_transport
		[ -z "$v2ray_transport" ] && v2ray_transport=1
		case $v2ray_transport in
		[1-9] | [1-2][0-9] | 3[0-3])
			echo
			echo
			echo -e "$yellow V2Ray transport protocol = $cyan${transport[$v2ray_transport - 1]}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac
	done
	v2ray_port_config
}
v2ray_port_config() {
	case $v2ray_transport in
	4 | 5 | 33)
		tls_config
		;;
	*)
		local random=$(shuf -i20001-65535 -n1)
		while :; do
			echo -e "Please enter the "$yellow"V2Ray"$none" port ["$magenta"1-65535"$none"]"
			read -p "$(echo -e "(Default port: ${cyan}${random}$none):")" v2ray_port
			[ -z "$v2ray_port" ] && v2ray_port=$random
			case $v2ray_port in
			[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
				echo
				echo
				echo -e "$yellow V2Ray port = $cyan$v2ray_port$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			*)
				error
				;;
			esac
		done
		if [[ $v2ray_transport -ge 18 && $v2ray_transport -ne 33 ]]; then
			v2ray_dynamic_port_start
		fi
		;;
	esac
}

v2ray_dynamic_port_start() {

	while :; do
		echo -e "Please enter the "$yellow"V2Ray"$none" dynamic port start "$none"range ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(Default start port: ${cyan}10000$none):")" v2ray_dynamic_port_start_input
		[ -z $v2ray_dynamic_port_start_input ] && v2ray_dynamic_port_start_input=10000
		case $v2ray_dynamic_port_start_input in
		$v2ray_port)
			echo
			echo " Cannot be the same as the V2Ray port...."
			echo
			echo -e " Current V2Ray port：${cyan}$v2ray_port${none}"
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
				echo
				echo
				echo -e "$yellow V2Ray dynamic port start = $cyan$v2ray_dynamic_port_start_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			*)
				error
				;;
		esac

	done

	if [[ $v2ray_dynamic_port_start_input -lt $v2ray_port ]]; then
		lt_v2ray_port=true
	fi

	v2ray_dynamic_port_end
}
v2ray_dynamic_port_end() {

	while :; do
		echo -e "Please enter the "$yellow"V2Ray"$none" dynamic port end "$none"range ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(Default end port: ${cyan}20000$none):")" v2ray_dynamic_port_end_input
		[ -z $v2ray_dynamic_port_end_input ] && v2ray_dynamic_port_end_input=20000
		case $v2ray_dynamic_port_end_input in
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])

			if [[ $v2ray_dynamic_port_end_input -le $v2ray_dynamic_port_start_input ]]; then
				echo
				echo " Cannot be less than or equal to the V2Ray dynamic port start range"
				echo
				echo -e " Current V2Ray dynamic port start：${cyan}$v2ray_dynamic_port_start_input${none}"
				error
			elif [ $lt_v2ray_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $v2ray_port ]]; then
				echo
				echo " V2Ray dynamic port end range cannot include V2Ray port..."
				echo
				echo -e " Current V2Ray port：${cyan}$v2ray_port${none}"
				error
			else
				echo
				echo
				echo -e "$yellow V2Ray dynamic port end = $cyan$v2ray_dynamic_port_end_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

}

tls_config() {

	echo
	local random=$(shuf -i20001-65535 -n1)
	while :; do
		echo -e "Please enter the "$yellow"V2Ray"$none" port ["$magenta"1-65535"$none"]，cannot select "$magenta"80"$none" or "$magenta"443"$none" port"
		read -p "$(echo -e "(Default port: ${cyan}${random}$none):")" v2ray_port
		[ -z "$v2ray_port" ] && v2ray_port=$random
		case $v2ray_port in
		80)
			echo
			echo " ...Cannot select port 80....."
			error
			;;
		443)
			echo
			echo " ..Cannot select port 443....."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			echo
			echo
			echo -e "$yellow V2Ray port = $cyan$v2ray_port$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac
	done

	while :; do
		echo
		echo -e "Please enter a ${magenta}correct domain name${none}, it must be correct, cannot be wrong!"
		read -p "(For example: 233blog.com): " domain
		[ -z "$domain" ] && error && continue
		echo
		echo
		echo -e "$yellow Your domain name = $cyan$domain$none"
		echo "----------------------------------------------------------------"
		break
	done
	get_ip
	echo
	echo
	echo -e "$yellow Please resolve $magenta$domain$none $yellow to: $cyan$ip$none"
	echo
	echo -e "$yellow Please resolve $magenta$domain$none $yellow to: $cyan$ip$none"
	echo
	echo -e "$yellow Please resolve $magenta$domain$none $yellow to: $cyan$ip$none"
	echo "----------------------------------------------------------------"
	echo

	while :; do

		read -p "$(echo -e "(Has it been resolved correctly: [${magenta}Y$none]):") " record
		if [[ -z "$record" ]]; then
			error
		else
			if [[ "$record" == [Yy] ]]; then
				domain_check
				echo
				echo
				echo -e "$yellow Domain name resolution = ${cyan}I am sure there is resolution$none"
				echo "----------------------------------------------------------------"
				echo
				break
			else
				error
			fi
		fi

	done

	if [[ $v2ray_transport -eq 4 ]]; then
		auto_tls_config
	else
		caddy=true
		install_caddy_info="open"
	fi

	if [[ $caddy ]]; then
		path_config_ask
	fi
}
auto_tls_config() {
	echo -e "

		Install Caddy to achieve automatic configuration of TLS

		If you have installed Nginx or Caddy

		$yellowAnd..can configure TLS yourself$none

		Then you don’t need to open automatic configuration TLS
		"
	echo "----------------------------------------------------------------"
	echo

	while :; do

		read -p "$(echo -e "(Whether to automatically configure TLS: [${magenta}Y/N$none]):") " auto_install_caddy
		if [[ -z "$auto_install_caddy" ]]; then
			error
		else
			if [[ "$auto_install_caddy" == [Yy] ]]; then
				caddy=true
				install_caddy_info="open"
				echo
				echo
				echo -e "$yellow Automatic configuration TLS = $cyan$install_caddy_info$none"
				echo "----------------------------------------------------------------"
				echo
				break
			elif [[ "$auto_install_caddy" == [Nn] ]]; then
				install_caddy_info="close"
				echo
				echo
				echo -e "$yellow Automatic configuration TLS = $cyan$install_caddy_info$none"
				echo "----------------------------------------------------------------"
				echo
				break
			else
				error
			fi
		fi

	done
}
path_config_ask() {
	echo
	while :; do
		echo -e "Whether to enable website camouflage and path shunt [${magenta}Y/N$none]"
		read -p "$(echo -e "(Default: [${cyan}N$none]):")" path_ask
		[[ -z $path_ask ]] && path_ask="n"

		case $path_ask in
		Y | y)
			path_config
			break
			;;
		N | n)
			echo
			echo
			echo -e "$yellow Website camouflage and path shunt = $cyan don’t want to configure $none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac
	done
}
path_config() {
	echo
	while :; do
		echo -e "Please enter the ${magenta}path used for shunting$none, for example /233blog, then just enter 233blog"
		read -p "$(echo -e "(Default: [${cyan}233blog$none]):")" path
		[[ -z $path ]] && path="233blog"

		case $path in
		*[/$]*)
			echo
			echo -e " Because this script is too bad...So the path for shunting cannot contain $red / $none or $red $ $none these two symbols.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Shunt path = ${cyan}/${path}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
	is_path=true
	proxy_site_config
}
proxy_site_config() {
	echo
	while :; do
		echo -e "Please enter ${magenta}a correct $none ${cyan}URL$none used as ${cyan}website camouflage$none, for example https://liyafly.com"
		echo -e "For example...Your current domain name is $green$domain$none, and the camouflage URL is https://liyafly.com"
		echo -e "Then when you open your domain name...The content displayed is from https://liyafly.com"
		echo -e "Actually it is a reverse proxy...Understand..."
		echo -e "If the camouflage is not successful...You can use v2ray config to modify the camouflage URL"
		read -p "$(echo -e "(Default: [${cyan}https://liyafly.com$none]):")" proxy_site
		[[ -z $proxy_site ]] && proxy_site="https://liyafly.com"

		case $proxy_site in
		*[#$]*)
			echo
			echo -e " Because this script is too bad...So the camouflage URL cannot contain $red # $none or $red $ $none these two symbols.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Camouflage URL = ${cyan}${proxy_site}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
}

blocked_hosts() {
	echo
	while :; do
		echo -e "Whether to enable ad blocking (will affect performance) [${magenta}Y/N$none]"
		read -p "$(echo -e "(Default [${cyan}N$none]):")" blocked_ad
		[[ -z $blocked_ad ]] && blocked_ad="n"

		case $blocked_ad in
		Y | y)
			blocked_ad_info="open"
			ban_ad=true
			echo
			echo
			echo -e "$yellow Ad blocking = $cyan open $none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		N | n)
			blocked_ad_info="close"
			echo
			echo
			echo -e "$yellow Ad blocking = $cyan close $none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac
	done
}
shadowsocks_config() {

	echo

	while :; do
		echo -e "Whether to configure ${yellow}Shadowsocks${none} [${magenta}Y/N$none]"
		read -p "$(echo -e "(Default [${cyan}N$none]):") " install_shadowsocks
		[[ -z "$install_shadowsocks" ]] && install_shadowsocks="n"
		if [[ "$install_shadowsocks" == [Yy] ]]; then
			echo
			shadowsocks=true
			shadowsocks_port_config
			break
		elif [[ "$install_shadowsocks" == [Nn] ]]; then
			break
		else
			error
		fi

	done

}

shadowsocks_port_config() {
	local random=$(shuf -i20001-65535 -n1)
	while :; do
		echo -e "Please enter the "$yellow"Shadowsocks"$none" port ["$magenta"1-65535"$none"], cannot be the same as the "$yellow"V2Ray"$none" port"
		read -p "$(echo -e "(Default port: ${cyan}${random}$none):") " ssport
		[ -z "$ssport" ] && ssport=$random
		case $ssport in
		$v2ray_port)
			echo
			echo " ...Cannot be exactly the same as the V2Ray port...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == [45] ]]; then
				local tls=ture
			fi
			if [[ $tls && $ssport == "80" ]] || [[ $tls && $ssport == "443" ]]; then
				echo
				echo -e "Because you have selected "$green"WebSocket + TLS $none or $green HTTP/2"$none" transmission protocol."
				echo
				echo -e "So you cannot choose "$magenta"80"$none" or "$magenta"443"$none" port"
				error
			elif [[ $v2ray_dynamic_port_start_input == $ssport || $v2ray_dynamic_port_end_input == $ssport ]]; then
				local multi_port="${v2ray_dynamic_port_start_input} - ${v2ray_dynamic_port_end_input}"
				echo
				echo " Sorry, this port conflicts with V2Ray dynamic port, the current V2Ray dynamic port range is: $multi_port"
				error
			elif [[ $v2ray_dynamic_port_start_input -lt $ssport && $ssport -le $v2ray_dynamic_port_end_input ]]; then
				local multi_port="${v2ray_dynamic_port_start_input} - ${v2ray_dynamic_port_end_input}"
				echo
				echo " Sorry, this port conflicts with V2Ray dynamic port, the current V2Ray dynamic port range is: $multi_port"
				error
			else
				echo
				echo
				echo -e "$yellow Shadowsocks port = $cyan$ssport$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

	shadowsocks_password_config
}
shadowsocks_password_config() {

	while :; do
		echo -e "Please enter the "$yellow"Shadowsocks"$none" password"
		read -p "$(echo -e "(Default password: ${cyan}233blog.com$none)"): " sspass
		[ -z "$sspass" ] && sspass="233blog.com"
		case $sspass in
		*[/$]*)
			echo
			echo -e " Because this script is too bad...So the password cannot contain $red / $none or $red $ $none these two symbols.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Shadowsocks password = $cyan$sspass$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac

	done

	shadowsocks_ciphers_config
}
shadowsocks_ciphers_config() {

	while :; do
		echo -e "Please select the "$yellow"Shadowsocks"$none" encryption protocol [${magenta}1-${#ciphers[*]}$none]"
		for ((i = 1; i <= ${#ciphers[*]}; i++)); do
			ciphers_show="${ciphers[$i - 1]}"
			echo
			echo -e "$yellow $i. $none${ciphers_show}"
		done
		echo
		read -p "$(echo -e "(Default encryption protocol: ${cyan}${ciphers[1]}$none)"):" ssciphers_opt
		[ -z "$ssciphers_opt" ] && ssciphers_opt=2
		case $ssciphers_opt in
		[1-3])
			ssciphers=${ciphers[$ssciphers_opt - 1]}
			echo
			echo
			echo -e "$yellow Shadowsocks encryption protocol = $cyan${ssciphers}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac

	done
	pause
}

install_info() {
	clear
	echo
	echo " ....Ready to install...Check if the configuration is correct..."
	echo
	echo "---------- Installation information -------------"
	echo
	echo -e "$yellow V2Ray transmission protocol = $cyan${transport[$v2ray_transport - 1]}$none"

	if [[ $v2ray_transport == [45] || $v2ray_transport == 33 ]]; then
		echo
		echo -e "$yellow V2Ray port = $cyan$v2ray_port$none"
		echo
		echo -e "$yellow Your domain name = $cyan$domain$none"
		echo
		echo -e "$yellow Domain name resolution = ${cyan}I am sure there is already a resolution$none"
		echo
		echo -e "$yellow Automatic configuration TLS = $cyan$install_caddy_info$none"

		if [[ $ban_ad ]]; then
			echo
			echo -e "$yellow Ad blocking = $cyan$blocked_ad_info$none"
		fi
		if [[ $is_path ]]; then
			echo
			echo -e "$yellow Path routing = ${cyan}/${path}$none"
		fi
	elif [[ $v2ray_transport -ge 18 && $v2ray_transport -ne 33 ]]; then
		echo
		echo -e "$yellow V2Ray port = $cyan$v2ray_port$none"
		echo
		echo -e "$yellow V2Ray dynamic port range = $cyan${v2ray_dynamic_port_start_input} - ${v2ray_dynamic_port_end_input}$none"

		if [[ $ban_ad ]]; then
			echo
			echo -e "$yellow Ad blocking = $cyan$blocked_ad_info$none"
		fi
	else
		echo
		echo -e "$yellow V2Ray port = $cyan$v2ray_port$none"

		if [[ $ban_ad ]]; then
			echo
			echo -e "$yellow Ad blocking = $cyan$blocked_ad_info$none"
		fi
	fi
	if [ $shadowsocks ]; then
		echo
		echo -e "$yellow Shadowsocks port = $cyan$ssport$none"
		echo
		echo -e "$yellow Shadowsocks password = $cyan$sspass$none"
		echo
		echo -e "$yellow Shadowsocks encryption protocol = $cyan${ssciphers}$none"
	else
		echo
		echo -e "$yellow Whether to configure Shadowsocks = ${cyan}Not configured${none}"
	fi
	echo
	echo "---------- END -------------"
	echo
	pause
	echo
}

domain_check() {
	# if [[ $cmd == "yum" ]]; then
	# 	yum install bind-utils -y
	# else
	# 	$cmd install dnsutils -y
	# fi
	# test_domain=$(dig $domain +short)
	test_domain=$(ping $domain -c 1 -W 2 | head -1)
	# test_domain=$(wget -qO- --header='accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$domain&type=A" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
	# test_domain=$(curl -sH 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$domain&type=A" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
	if [[ ! $(echo $test_domain | grep $ip) ]]; then
		echo
		echo -e "$red Check domain name resolution error....$none"
		echo
		echo -e " Your domain name: $yellow$domain$none is not resolved to: $cyan$ip$none"
		echo
		echo -e " PING test result: $cyan$test_domain$none"
		echo
		echo "Note...If your domain name is resolved using Cloudflare...in DNS, set (Proxy status / 代理状态) to (DNS only / 仅限 DNS)"
		echo
		exit 1
	fi
}

install_caddy() {
	# download caddy file then install
	_load download-caddy.sh
	_download_caddy_file
	_install_caddy_service
	caddy_config

}
caddy_config() {
	# local email=$(shuf -i1-10000000000 -n1)
	_load caddy-config.sh

	# systemctl restart caddy
	do_service restart caddy
}

install_v2ray() {
	$cmd update -y
	if [[ $cmd == "apt-get" ]]; then
		$cmd install -y lrzsz git zip unzip curl wget qrencode libcap2-bin dbus
	else
		# $cmd install -y lrzsz git zip unzip curl wget qrencode libcap iptables-services
		$cmd install -y lrzsz git zip unzip curl wget qrencode libcap
	fi
	ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	[ -d /etc/v2ray ] && rm -rf /etc/v2ray
	# date -s "$(curl -sI g.cn | grep Date | cut -d' ' -f3-6)Z"
	_sys_timezone
	_sys_time

	if [[ $local_install ]]; then
		if [[ ! -d $(pwd)/config ]]; then
			echo
			echo -e "$red Oh...installation failed...$none"
			echo
			echo -e " Please make sure you have the complete upload 233v2.com V2Ray one-click installation script & management script to the current ${green}$(pwd) $none directory"
			echo
			exit 1
		fi
		mkdir -p /etc/v2ray/233boy/v2ray
		cp -rf $(pwd)/* /etc/v2ray/233boy/v2ray
	else
		pushd /tmp
		git clone https://github.com/233boy/v2ray -b "$_gitbranch" /etc/v2ray/233boy/v2ray --depth=1
		popd

	fi

	if [[ ! -d /etc/v2ray/233boy/v2ray ]]; then
		echo
		echo -e "$red Oh...clone script repository error...$none"
		echo
		echo -e " Friendly reminder..... Please try to install Git yourself: ${green}$cmd install -y git $none and then install this script"
		echo
		exit 1
	fi

	# download v2ray file then install
	_load download-v2ray.sh
	_download_v2ray_file
	_install_v2ray_service
	_mkdir_dir
}

config() {
	cp -f /etc/v2ray/233boy/v2ray/config/backup.conf $backup
	cp -f /etc/v2ray/233boy/v2ray/v2ray.sh $_v2ray_sh
	chmod +x $_v2ray_sh

	v2ray_id=$uuid
	alterId=0
	ban_bt=true
	if [[ $v2ray_transport -ge 18 && $v2ray_transport -ne 33 ]]; then
		v2ray_dynamicPort_start=${v2ray_dynamic_port_start_input}
		v2ray_dynamicPort_end=${v2ray_dynamic_port_end_input}
	fi
	_load config.sh

	# if [[ $cmd == "apt-get" ]]; then
	# 	cat >/etc/network/if-pre-up.d/iptables <<-EOF
	# 		#!/bin/sh
	# 		/sbin/iptables-restore < /etc/iptables.rules.v4
	# 		/sbin/ip6tables-restore < /etc/iptables.rules.v6
	# 	EOF
	# 	chmod +x /etc/network/if-pre-up.d/iptables
	# 	# else
	# 	# 	[ $(pgrep "firewall") ] && systemctl stop firewalld
	# 	# 	systemctl mask firewalld
	# 	# 	systemctl disable firewalld
	# 	# 	systemctl enable iptables
	# 	# 	systemctl enable ip6tables
	# 	# 	systemctl start iptables
	# 	# 	systemctl start ip6tables
	# fi

	# systemctl restart v2ray
	do_service restart v2ray
	backup_config

}

backup_config() {
	sed -i "18s/=1/=$v2ray_transport/; 21s/=2333/=$v2ray_port/; 24s/=$old_id/=$uuid/" $backup
	if [[ $v2ray_transport -ge 18 && $v2ray_transport -ne 33 ]]; then
		sed -i "30s/=10000/=$v2ray_dynamic_port_start_input/; 33s/=20000/=$v2ray_dynamic_port_end_input/" $backup
	fi
	if [[ $shadowsocks ]]; then
		sed -i "42s/=/=true/; 45s/=6666/=$ssport/; 48s/=233blog.com/=$sspass/; 51s/=chacha20-ietf/=$ssciphers/" $backup
	fi
	[[ $v2ray_transport == [45] || $v2ray_transport == 33 ]] && sed -i "36s/=233blog.com/=$domain/" $backup
	[[ $caddy ]] && sed -i "39s/=/=true/" $backup
	[[ $ban_ad ]] && sed -i "54s/=/=true/" $backup
	if [[ $is_path ]]; then
		sed -i "57s/=/=true/; 60s/=233blog/=$path/" $backup
		sed -i "63s#=https://liyafly.com#=$proxy_site#" $backup
	fi
}

get_ip() {
	# ip=$(curl -s https://ipinfo.io/ip)
	# [[ -z $ip ]] && ip=$(curl -s https://api.ip.sb/ip)
	# [[ -z $ip ]] && ip=$(curl -s https://api.ipify.org)
	# [[ -z $ip ]] && ip=$(curl -s https://ip.seeip.org)
	# [[ -z $ip ]] && ip=$(curl -s https://ifconfig.co/ip)
	# [[ -z $ip ]] && ip=$(curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	# [[ -z $ip ]] && ip=$(curl -s icanhazip.com)
	# [[ -z $ip ]] && ip=$(curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	export "$(wget -4 -qO- https://dash.cloudflare.com/cdn-cgi/trace | grep ip=)" >/dev/null 2>&1
	[[ -z $ip ]] && export "$(wget -6 -qO- https://dash.cloudflare.com/cdn-cgi/trace | grep ip=)" >/dev/null 2>&1
	[[ -z $ip ]] && echo -e "\n$red Failed to get IP, throw away this garbage little chicken!$none\n" && exit
}

error() {

	echo -e "\n$red Input error!$none\n"

}

pause() {

	read -rsp "$(echo -e "Press $green Enter key $none to continue....or press $red Ctrl + C $none to cancel.")" -d $'\n'
	echo
}
do_service() {
	if [[ $systemd ]]; then
		systemctl $1 $2
	else
		service $2 $1
	fi
}
show_config_info() {
	clear
	_load v2ray-info.sh
	_v2_args
	_v2_info
	_load ss-info.sh

}

install() {
	if [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f $backup && -d /etc/v2ray/233boy/v2ray ]]; then
		echo
		echo " Big brother...you have installed V2Ray...no need to reinstall"
		echo
		echo -e " $yellowEnter ${cyan}v2ray $yellowto manage V2Ray${none}"
		echo
		exit 1
	elif [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f /etc/v2ray/233blog_v2ray_backup.txt && -d /etc/v2ray/233boy/v2ray ]]; then
		echo
		echo "  If you need to continue installing...please uninstall the old version first"
		echo
		echo -e " $yellowEnter ${cyan}v2ray uninstall $yellowto uninstall${none}"
		echo
		exit 1
	fi
	v2ray_config
	blocked_hosts
	shadowsocks_config
	install_info
	# [[ $caddy ]] && domain_check
	install_v2ray
	if [[ $caddy || $v2ray_port == "80" ]]; then
		if [[ $cmd == "yum" ]]; then
			[[ $(pgrep "httpd") ]] && systemctl stop httpd
			[[ $(command -v httpd) ]] && yum remove httpd -y
		else
			[[ $(pgrep "apache2") ]] && service apache2 stop
			[[ $(command -v apache2) ]] && apt-get remove apache2* -y
		fi
	fi
	[[ $caddy ]] && install_caddy

	## bbr
	# _load bbr.sh
	# _try_enable_bbr

	get_ip
	config
	show_config_info
}
uninstall() {

	if [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f $backup && -d /etc/v2ray/233boy/v2ray ]]; then
		. $backup
		if [[ $mark ]]; then
			_load uninstall.sh
		else
			echo
			echo -e " $yellowEnter ${cyan}v2ray uninstall $yellowto uninstall${none}"
			echo
		fi

	elif [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f /etc/v2ray/233blog_v2ray_backup.txt && -d /etc/v2ray/233boy/v2ray ]]; then
		echo
		echo -e " $yellowEnter ${cyan}v2ray uninstall $yellowto uninstall${none}"
		echo
	else
		echo -e "
		$red Big brother...you seem to have not installed V2Ray....uninstall a chicken...
		$none

		Note...Only supports uninstalling V2Ray one-click installation scripts provided by me (233v2.com)
		" && exit 1
	fi

}

args=$1
_gitbranch=$2
[ -z $1 ] && args="online"
case $args in
online)
	#hello world
	[[ -z $_gitbranch ]] && _gitbranch="master"
	;;
local)
	local_install=true
	;;
*)
	echo
	echo -e " The parameter you entered <$red $args $none> ...what the hell is this...the script doesn't know it"
	echo
	echo -e " This crappy script only supports inputting $green local / online $none parameters"
	echo
	echo -e " Enter $yellow local $none to use local installation"
	echo
	echo -e " Enter $yellow online $none to use online installation (default)"
	echo
	exit 1
	;;
esac

clear
while :; do
	echo
	echo "........... V2Ray one-click installation script & management script by 233v2.com .........."
	echo
	echo "Help: https://233v2.com/post/1/"
	echo
	echo "Installation tutorial: https://233v2.com/post/2/"
	echo
	echo " 1. Install"
	echo
	echo " 2. Uninstall"
	echo
	if [[ $local_install ]]; then
		echo -e "$yellow Friendly reminder...local installation is enabled..$none"
		echo
	fi
	read -p "$(echo -e "Please select [${magenta}1-2$none]:")" choose
	case $choose in
	1)
		install
		break
		;;
	2)
		uninstall
		break
		;;
	*)
		error
		;;
	esac
done

