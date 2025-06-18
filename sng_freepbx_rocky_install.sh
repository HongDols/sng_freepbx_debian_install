#!/bin/bash
#####################################################################################
# FreePBX 17 Rocky Linux 9.6 설치 스크립트
# Copyright 2024 by Sangoma Technologies (변환: Rocky Linux 9.6)
# 본 스크립트는 GPL v3 라이선스를 따릅니다.
#####################################################################################
#                                               FreePBX 17                          #
#####################################################################################
set -e
SCRIPTVER="1.0-rocky"
ASTVERSION=22
PHPVERSION="8.2"
LOG_FOLDER="/var/log/pbx"
LOG_FILE="${LOG_FOLDER}/freepbx17-install-$(date '+%Y.%m.%d-%H.%M.%S').log"
log=$LOG_FILE
SANE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 루트 권한 체크
if [[ $EUID -ne 0 ]]; then
   echo "이 스크립트는 root 권한으로 실행해야 합니다."
   exit 1
fi

# PATH 설정
export PATH=$SANE_PATH

# 명령행 옵션 처리
while [[ $# -gt 0 ]]; do
	case $1 in
		--dev)
			dev=true
			shift
			;;
		--testing)
			testrepo=true
			shift
			;;
		--nofreepbx)
			nofpbx=true
			shift
			;;
		--noasterisk)
			noast=true
			shift
			;;
		--opensourceonly)
			opensourceonly=true
			shift
			;;
		--noaac)
			noaac=true
			shift
			;;
		--dahdi)
			dahdi=true
			shift
			;;
		--dahdi-only)
			nofpbx=true
			noast=true
			noaac=true
			dahdi=true
			shift
			;;
		--nochrony)
			nochrony=true
			shift
			;;
		--npmmirror)
			NPM_MIRROR=$2
			shift; shift
			;;
		-*)
			echo "알 수 없는 옵션 $1"
			exit 1
			;;
		*)
			echo "알 수 없는 인수 \"$1\""
			exit 1
			;;
	esac
done

# 로그 폴더 및 파일 생성
mkdir -p "${LOG_FOLDER}"
touch "${LOG_FILE}"

# 표준 에러를 로그 파일로 리다이렉트
exec 2>>"${LOG_FILE}"

# 로그 함수
log() {
	echo "$(date +"%Y-%m-%d %T") - $*" >> "$LOG_FILE"
}

message() {
	echo "$(date +"%Y-%m-%d %T") - $*"
	log "$*"
}

# 현재 단계 설정 함수
setCurrentStep () {
	currentStep="$1"
	message "${currentStep}"
}

# 설치 정리 함수
terminate() {
	message "스크립트 종료"
	rm -f "$pidfile"
}

# 오류 처리 함수
errorHandler() {
	log "****** 설치 실패 *****"
	message "설치가 ${currentStep} 단계에서 실패했습니다. 자세한 내용은 로그 ${LOG_FILE}를 확인하세요."
	message "오류 위치: $1, 종료 코드: $2 (마지막 명령: $3)"
	exit "$2"
}

# 패키지 설치 확인 함수
isinstalled() {
	if rpm -q "$@" >/dev/null 2>&1; then
		true
	else
		false
	fi
}

# 패키지 설치 함수
pkg_install() {
    log "############################### "
    PKG=("$@")
    if isinstalled "${PKG[@]}"; then
        log "${PKG[*]} 이미 설치됨 ...."
    else
        message "설치 중: ${PKG[*]} ...."
        dnf install -y "${PKG[@]}" >> "$log"
        if isinstalled "${PKG[@]}"; then
            message "${PKG[*]} 설치 성공...."
        else
            message "${PKG[*]} 설치 실패...."
            message "의존 패키지 ${PKG[*]} 설치 실패로 설치 프로세스를 종료합니다...."
            terminate
        fi
    fi
    log "############################### "
}

# Asterisk 설치 함수
install_asterisk() {
	astver=$1
	ASTPKGS=("addons"
		"addons-bluetooth"
		"addons-core"
		"addons-mysql"
		"addons-ooh323"
		"core"
		"curl"
		"dahdi"
		"doc"
		"odbc"
		"ogg"
		"flite"
		"g729"
		"resample"
		"snmp"
		"speex"
		"sqlite3"
		"res-digium-phone"
		"voicemail"
	)

	# 디렉토리 생성
	mkdir -p /var/lib/asterisk/moh
	pkg_install asterisk"$astver"

	for i in "${!ASTPKGS[@]}"; do
		pkg_install asterisk"$astver"-"${ASTPKGS[$i]}"
	done

	pkg_install asterisk"$astver".0-freepbx-asterisk-modules
	pkg_install asterisk-version-switch
	pkg_install asterisk-sounds-*
}

# 저장소 설정 함수
setup_repositories() {
	# EPEL 저장소 추가
	dnf install -y epel-release >> "$log"
	
	# Remi 저장소 추가 (PHP 8.2용)
	dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm >> "$log"
	
	# FreePBX 저장소 추가
	if [ "$testrepo" ] ; then
		# 테스트 저장소 (실제로는 Sangoma에서 제공하는 저장소 URL로 변경 필요)
		cat <<EOF > /etc/yum.repos.d/freepbx-test.repo
[freepbx-test]
name=FreePBX Test Repository
baseurl=http://deb.freepbx.org/freepbx17-dev/el9/\$basearch/
enabled=1
gpgcheck=0
EOF
	else
		# 프로덕션 저장소
		cat <<EOF > /etc/yum.repos.d/freepbx-prod.repo
[freepbx-prod]
name=FreePBX Production Repository
baseurl=http://deb.freepbx.org/freepbx17-prod/el9/\$basearch/
enabled=1
gpgcheck=0
EOF
	fi

	if [ ! "$noaac" ] ; then
		# RPM Fusion 저장소 추가 (ffmpeg용)
		dnf install -y https://download1.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm >> "$log"
	fi
}

# 커널 호환성 체크 함수
check_kernel_compatibility() {
    local curr_kernel_version=$1
    # Rocky Linux 9.6의 기본 커널은 DAHDI와 호환됩니다
    message "커널 버전 $curr_kernel_version 확인 완료"
}

# 서명 새로고침 함수
refresh_signatures() {
  fwconsole ma refreshsignatures >> "$log"
}

# 서비스 체크 함수
check_services() {
    services=("fail2ban" "firewalld")
    for service in "${services[@]}"; do
        service_status=$(systemctl is-active "$service")
        if [[ "$service_status" != "active" ]]; then
            message "서비스 $service가 활성화되지 않았습니다. 실행 중인지 확인하세요."
        fi
    done

    httpd_status=$(systemctl is-active httpd)
    if [[ "$httpd_status" == "active" ]]; then
        httpd_process=$(netstat -anp | awk '$4 ~ /:80$/ {sub(/.*\//,"",$7); print $7}')
        if [ "$httpd_process" == "httpd" ]; then
            message "Apache(httpd) 서비스가 포트 80에서 실행 중입니다."
        else
            message "Apache(httpd)가 포트 80에서 실행되지 않습니다."
        fi
    else
        message "Apache(httpd) 서비스가 활성화되지 않았습니다. 서비스를 활성화하세요"
    fi
}

# PHP 버전 체크 함수
check_php_version() {
    php_version=$(php -v | grep built: | awk '{print $2}')
    if [[ "${php_version:0:3}" == "8.2" ]]; then
        message "설치된 PHP 버전 $php_version이 FreePBX와 호환됩니다."
    else
        message "설치된 PHP 버전 $php_version이 FreePBX와 호환되지 않습니다. PHP 버전 '8.2.x'를 설치하세요"
    fi
}

# 모듈 상태 확인 함수
verify_module_status() {
    modules_list=$(fwconsole ma list | grep -Ewv "Enabled|----|Module|No repos")
    if [ -z "$modules_list" ]; then
        message "모든 모듈이 활성화되었습니다."
    else
        message "활성화되지 않은 모듈 목록:"
        message "$modules_list"
    fi
}

# 네트워크 포트 검사 함수
inspect_network_ports() {
    local ports_services=(
        82 restapps
        83 restapi
        81 ucp
        80 acp
        84 hpro
        "" leport
        "" sslrestapps
        "" sslrestapi
        "" sslucp
        "" sslacp
        "" sslhpro
        "" sslsngphone
    )

    for (( i=0; i<${#ports_services[@]}; i+=2 )); do
        port="${ports_services[i]}"
        service="${ports_services[i+1]}"
        port_set=$(fwconsole sa ports | grep "$service" | cut -d'|' -f 2 | tr -d '[:space:]')

        if [ "$port_set" == "$port" ]; then
            message "$service 모듈이 기본 포트에 할당되었습니다."
        else
            message "$service 모듈이 포트 $port_set 대신 포트 $port에 할당되어야 합니다"
        fi
    done
}

# 실행 중인 프로세스 검사 함수
inspect_running_processes() {
    processes=$(fwconsole pm2 --list |  grep -Ewv "online|----|Process")
    if [ -z "$processes" ]; then
        message "오프라인 프로세스가 없습니다."
    else
        message "오프라인 프로세스 목록:"
        message "$processes"
    fi
}

# FreePBX 체크 함수
check_freepbx() {
     if ! rpm -q freepbx >/dev/null 2>&1; then
        message "FreePBX가 설치되지 않았습니다. 계속하려면 FreePBX를 설치하세요."
    else
        verify_module_status
	if [ ! "$opensourceonly" ] ; then
        	inspect_network_ports
	fi
        inspect_running_processes
        inspect_job_status=$(fwconsole job --list)
        message "작업 목록 : $inspect_job_status"
    fi
}

# Digium 전화 버전 체크 함수
check_digium_phones_version() {
    installed_version=$(asterisk -rx 'digium_phones show version' | awk '/Version/{print $NF}' 2>/dev/null)
    if [[ -n "$installed_version" ]]; then
        required_version="21.0_3.6.8"
        present_version=$(echo "$installed_version" | sed 's/_/./g')
        required_version=$(echo "$required_version" | sed 's/_/./g')
        if rpm --compare-versions "$present_version" "lt" "$required_version" >/dev/null 2>&1; then
            message "Digium Phones 모듈의 더 새로운 버전을 사용할 수 있습니다."
        else
            message "설치된 Digium Phones 모듈 버전: ($installed_version)"
        fi
    else
        message "Digium Phones 모듈 버전 확인에 실패했습니다."
    fi
}

# Asterisk 체크 함수
check_asterisk() {
    if ! rpm -q asterisk >/dev/null 2>&1; then
        message "Asterisk가 설치되지 않았습니다. 계속하려면 Asterisk를 설치하세요."
    else
        check_asterisk_version=$(asterisk -V)
        message "$check_asterisk_version"
	if asterisk -rx "module show" | grep -q "res_digium_phone.so"; then
            check_digium_phones_version
        else
            message "Digium Phones 모듈이 로드되지 않았습니다. 올바르게 설치되고 로드되었는지 확인하세요."
        fi
    fi
}

# 패키지 홀드 함수
hold_packages() {
    local packages=("sangoma-pbx17" "nodejs" "node-*")
    if [ ! "$nofpbx" ] ; then
        packages+=("freepbx17")
    fi

    for pkg in "${packages[@]}"; do
        dnf mark install "$pkg" >> "$log" 2>/dev/null || true
    done
}

################################################################################################################
kernel=$(uname -a)
host=$(hostname)
fqdn="$(hostname -f)" || true

# wget 설치
pkg_install wget

# 스크립트 중복 실행 방지
pidfile='/var/run/freepbx17_installer.pid'

if [ -f "$pidfile" ]; then
	old_pid=$(cat "$pidfile")
	if ps -p "$old_pid" > /dev/null; then
		message "FreePBX 17 설치 프로세스가 이미 진행 중입니다 (PID=$old_pid), 새 프로세스를 시작하지 않습니다"
		exit 1
	else
		log "오래된 PID 파일 제거"
		rm -f "${pidfile}"
	fi
fi
echo "$$" > "$pidfile"

setCurrentStep "설치 시작."
trap 'errorHandler "$LINENO" "$?" "$BASH_COMMAND"' ERR
trap "terminate" EXIT

start=$(date +%s)
message "  $host $kernel에 대한 FreePBX 17 설치 프로세스 시작"
message "  프로세스에 대한 자세한 내용은 $log를 참조하세요..."
log "  스크립트 v$SCRIPTVER 실행 중..."

setCurrentStep "설치 환경 정리"
# 깨진 설치 수정
dnf check-update >> "$log" 2>&1 || true
dnf autoremove -y >> "$log"

dnf update -y >> "$log"

# 기본 설정
setCurrentStep "기본 설정 구성"
# postfix 설정
echo "postfix postfix/mailname string ${fqdn}" | debconf-set-selections 2>/dev/null || true

# 저장소 설정에 필요한 패키지 설치
pkg_install dnf-utils
pkg_install gnupg2

setCurrentStep "저장소 설정"
setup_repositories

kernel_version=$(uname -r | cut -d'-' -f1-2)

message "커널 $kernel_version에서 FreePBX 17을 설치하고 있습니다."
message "DAHDI를 사용할 계획이 있다면:"
message "DAHDI 옵션을 선택하여 스크립트가 DAHDI를 구성하도록 하거나"
message "DAHDI 지원 커널을 실행하고 있는지 확인하세요."

if [ "$dahdi" ]; then
    setCurrentStep "적절한 커널 업그레이드 및 버전 설치 허용"
    check_kernel_compatibility "$kernel_version"
fi

setCurrentStep "저장소 업데이트"
dnf update -y >> "$log"

# 저장소 정책 로그
dnf repolist >> "$log"

# 서비스 자동 시작 방지
systemctl mask tftp >> "$log" 2>&1 || true
if [ "$nochrony" != true ]; then
	systemctl mask chronyd >> "$log" 2>&1 || true
fi

# 의존 패키지 설치
setCurrentStep "필수 패키지 설치"
DEPPRODPKGS=(
	"redis"
	"ghostscript"
	"libtiff-tools"
	"iptables-services"
	"net-tools"
	"rsyslog"
	"avahi"
	"nmap"
	"httpd"
	"zip"
	"incron"
	"wget"
	"vim"
	"openssh-server"
	"rsync"
	"mariadb-server"
	"mariadb"
	"bison"
	"flex"
	"flite"
	"php${PHPVERSION}"
	"php${PHPVERSION}-curl"
	"php${PHPVERSION}-zip"
	"php${PHPVERSION}-redis"
	"php${PHPVERSION}-curl"
	"php${PHPVERSION}-cli"
	"php${PHPVERSION}-common"
	"php${PHPVERSION}-mysqlnd"
	"php${PHPVERSION}-gd"
	"php${PHPVERSION}-mbstring"
	"php${PHPVERSION}-intl"
	"php${PHPVERSION}-xml"
	"php${PHPVERSION}-bz2"
	"php${PHPVERSION}-ldap"
	"php${PHPVERSION}-sqlite3"
	"php${PHPVERSION}-bcmath"
	"php${PHPVERSION}-soap"
	"php${PHPVERSION}-ssh2"
	"php-pear"
	"curl"
	"sox"
	"mpg123"
	"sqlite"
	"git"
	"uuid"
	"unixODBC"
	"sudo"
	"subversion"
	"nodejs"
	"npm"
	"ipset"
	"iptables"
	"fail2ban"
	"htop"
	"postfix"
	"tcpdump"
	"sngrep"
	"tftp-server"
	"xinetd"
	"lame"
	"screen"
	"sysstat"
	"ca-certificates"
 	"cronie"
 	"python3-PyMySQL"
 	"at"
 	"avahi-tools"
	"nss-mdns"
	"mailx"
	"liburiparser"
	"ffmpeg"
	"python3-mysqldb"
	"python3"
	"pkgconf"
	"libicu-devel"
	"libsrtp2"
	"libspandsp"
	"ncurses"
	"autoconf"
	"libical"
	"libneon"
	"net-snmp"
	"libtonezone"
	"bluez-libs"
	"unbound-libs"
	"freetds"
	"speexdsp"
	"iksemel"
	"libresample"
	"gmime30"
	"cyrus-sasl"
	"ImageMagick"
)
DEPDEVPKGS=(
	"net-snmp-devel"
	"libtonezone-devel"
	"postgresql-devel"
	"lua-devel"
	"libpri-devel"
	"bluez-libs-devel"
	"unbound-devel"
	"speexdsp-devel"
	"iksemel-devel"
	"libresample-devel"
	"gmime30-devel"
	"cyrus-sasl-devel"
	"ncurses-devel"
	"openssl-devel"
	"libxml2-devel"
	"newt-devel"
	"sqlite-devel"
	"unixODBC-devel"
	"uuid-devel"
	"alsa-lib-devel"
	"libogg-devel"
	"libvorbis-devel"
	"libcurl-devel"
	"libical-devel"
	"libneon-devel"
	"libsrtp2-devel"
	"libspandsp-devel"
	"jansson-devel"
	"liburiparser-devel"
	"python3-devel"
	"mariadb-devel"
	"gcc"
	"gcc-c++"
	"make"
	"automake"
	"autoconf"
	"libtool"
	"bison"
	"flex"
)
if [ $dev ]; then
	DEPPKGS=("${DEPPRODPKGS[@]}" "${DEPDEVPKGS[@]}")
else
	DEPPKGS=("${DEPPRODPKGS[@]}")
fi
if [ "$nochrony" != true ]; then
	DEPPKGS+=("chrony")
fi
for i in "${!DEPPKGS[@]}"; do
	pkg_install "${DEPPKGS[$i]}"
done

# postfix 설정
if rpm -q postfix >/dev/null 2>&1; then
    warning_message="# WARNING: inet_interfaces를 127.0.0.1이 아닌 IP로 변경하면 Postfix가 외부 네트워크 연결에 노출될 수 있습니다.\n# 특정 네트워크 요구사항이 있고 그 의미를 이해하는 경우에만 이 설정을 수정하세요."

    if ! grep -q "WARNING: inet_interfaces" /etc/postfix/main.cf; then
        sed -i "/^inet_interfaces\s*=/i $warning_message" /etc/postfix/main.cf
    fi

    sed -i "s/^inet_interfaces\s*=.*/inet_interfaces = 127.0.0.1/" /etc/postfix/main.cf

    systemctl restart postfix
fi

# DAHDI 카드 지원 설치 (--dahdi 옵션이 제공된 경우)
if [ "$dahdi" ]; then
    message "DAHDI 카드 지원 설치 중..."
    DAHDIPKGS=("asterisk${ASTVERSION}-dahdi"
           "dahdi-firmware"
           "dahdi-linux"
           "dahdi-linux-devel"
           "dahdi-tools"
           "libpri"
           "libpri-devel"
           "wanpipe"
           "wanpipe-devel"
	)

        for i in "${!DAHDIPKGS[@]}"; do
                pkg_install "${DAHDIPKGS[$i]}"
        done
fi

# libfdk-aac2 설치
if [ "$noaac" ] ; then
	message "noaac 옵션으로 인해 libfdk-aac2 설치를 건너뜁니다"
else
	pkg_install libfdk-aac2
fi

setCurrentStep "불필요한 패키지 제거"
dnf autoremove -y >> "$log"

execution_time="$(($(date +%s) - start))"
message "모든 의존 패키지 설치 실행 시간 : $execution_time s"

setCurrentStep "폴더 및 asterisk 설정"
groupExists="$(getent group asterisk || echo '')"
if [ "${groupExists}" = "" ]; then
	groupadd -r asterisk
fi

userExists="$(getent passwd asterisk || echo '')"
if [ "${userExists}" = "" ]; then
	useradd -r -g asterisk -d /var/lib/asterisk -M -s /sbin/nologin asterisk
fi

# /tftpboot 디렉토리 생성
mkdir -p /tftpboot
chown -R asterisk:asterisk /tftpboot

# tftp 서비스 시작
systemctl unmask tftp >> "$log" 2>&1 || true
systemctl start tftp >> "$log" 2>&1 || true
if [ "$nochrony" != true ]; then
	systemctl unmask chronyd >> "$log" 2>&1 || true
	systemctl start chronyd >> "$log" 2>&1 || true
fi

# asterisk 사운드 디렉토리 생성
mkdir -p /var/lib/asterisk/sounds
chown -R asterisk:asterisk /var/lib/asterisk

# OpenSSL 설정 변경 (katana와 호환되도록)
sed -i -e 's/^openssl_conf = openssl_init$/openssl_conf = default_conf/' /etc/ssl/openssl.cnf

isSSLConfigAdapted=$(grep "FreePBX 17 changes" /etc/ssl/openssl.cnf |wc -l)
if [ "0" = "${isSSLConfigAdapted}" ]; then
	cat <<EOF >> /etc/ssl/openssl.cnf
# FreePBX 17 changes - begin
[ default_conf ]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=1
# FreePBX 17 changes - end
EOF
fi

# IPv4 우선순위 설정
sed -i 's/^#\s*precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' /etc/gai.conf

# screen 설정
isScreenRcAdapted=$(grep "FreePBX 17 changes" /root/.screenrc |wc -l)
if [ "0" = "${isScreenRcAdapted}" ]; then
	cat <<EOF >> /root/.screenrc
# FreePBX 17 changes - begin
hardstatus alwayslastline
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{=kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{B}%Y-%m-%d %{W}%c %{g}]'
# FreePBX 17 changes - end
EOF
fi

# VIM 설정 (마우스 복사 붙여넣기용)
isVimRcAdapted=$(grep "FreePBX 17 changes" /etc/vimrc |wc -l)
if [ "0" = "${isVimRcAdapted}" ]; then
	cat <<EOF >> /etc/vimrc
" FreePBX 17 changes - begin
" 이 파일은 시작 시 기본 vim 옵션을 로드하고 나중에 다시 로드되지 않도록 방지합니다.
" 이 파일 끝에 원하는 만큼의 옵션을 추가하거나 기본 설정을 덮어쓸 수 있습니다.

" 기본값 로드
source \$VIMRUNTIME/defaults.vim

" 사용자가 로컬 vimrc(~/.vimrc)가 없는 경우 나중에 기본값이 다시 로드되지 않도록 방지
let skip_defaults_vim = 1

" 더 많은 옵션 설정 (/usr/share/vim/vim80/defaults.vim의 설정 덮어쓰기)
" 원하는 만큼의 옵션을 추가하세요

" 마우스 모드를 'r'로 설정
if has('mouse')
  set mouse=r
endif
" FreePBX 17 changes - end
EOF
fi

# DNF 설정 (기존 구성 덮어쓰지 않음)
dnfNoOverwrite=$(grep "conf_def" /etc/dnf/dnf.conf |wc -l)
if [ "0" = "${dnfNoOverwrite}" ]; then
        cat <<EOF >> /etc/dnf/dnf.conf
conf_def=1
conf_confold=1
EOF
fi

# Asterisk 설치
if [ "$noast" ] ; then
	message "noasterisk 옵션으로 인해 Asterisk 설치를 건너뜁니다"
else
	setCurrentStep "Asterisk 패키지 설치 중."
	install_asterisk $ASTVERSION
fi

# PBX 의존 패키지 설치
setCurrentStep "FreePBX 패키지 설치"

FPBXPKGS=("sysadmin17"
	   "sangoma-pbx17"
	   "ffmpeg"
   )
for i in "${!FPBXPKGS[@]}"; do
	pkg_install "${FPBXPKGS[$i]}"
done

# freepbx.ini 파일 활성화
setCurrentStep "모듈 활성화."
mkdir -p /var/lib/php/session

# 기본 설정 파일 생성
mkdir -p /etc/asterisk
touch /etc/asterisk/extconfig_custom.conf
touch /etc/asterisk/extensions_override_freepbx.conf
touch /etc/asterisk/extensions_additional.conf
touch /etc/asterisk/extensions_custom.conf
chown -R asterisk:asterisk /etc/asterisk

setCurrentStep "fail2ban 재시작"
systemctl restart fail2ban  >> "$log"

if [ "$nofpbx" ] ; then
  message "nofreepbx 옵션으로 인해 FreePBX 17 설치를 건너뜁니다"
else
  setCurrentStep "FreePBX 17 설치"
  pkg_install ioncube-loader-82
  pkg_install freepbx17

  if [ -n "$NPM_MIRROR" ] ; then
    setCurrentStep "환경 변수 npm_config_registry=$NPM_MIRROR 설정"
    export npm_config_registry="$NPM_MIRROR"
  fi

  # 오픈소스만 필요한 경우 상용 모듈 제거
  if [ "$opensourceonly" ]; then
    setCurrentStep "상용 모듈 제거"
    fwconsole ma list | awk '/Commercial/ {print $2}' | xargs -I {} fwconsole ma -f remove {} >> "$log"
    # 방화벽 모듈도 제거 (상용 sysadmin 모듈에 의존)
    fwconsole ma -f remove firewall >> "$log" || true
  fi

  if [ "$dahdi" ]; then
    fwconsole ma downloadinstall dahdiconfig >> "$log"
    echo 'export PERL5LIB=$PERL5LIB:/etc/wanpipe/wancfg_zaptel' | sudo tee -a /root/.bashrc
  fi

  setCurrentStep "모든 로컬 모듈 설치"
  fwconsole ma installlocal >> "$log"

  setCurrentStep "FreePBX 17 모듈 업그레이드"
  fwconsole ma upgradeall >> "$log"

  setCurrentStep "FreePBX 17 리로드 및 재시작"
  fwconsole reload >> "$log"
  fwconsole restart >> "$log"

  if [ "$opensourceonly" ]; then
    # sysadmin 상용 모듈용 sysadmin 헬퍼 패키지 제거
    message "sysadmin17 제거"
    dnf remove -y sysadmin17 >> "$log"
    # 상용 모듈용 ionCube 로더 제거
    message "ioncube-loader-82 제거"
    dnf remove -y ioncube-loader-82 >> "$log"
  fi
fi

setCurrentStep "설치 프로세스 마무리"
systemctl daemon-reload >> "$log"
if [ ! "$nofpbx" ] ; then
  systemctl enable freepbx >> "$log"
fi

# apache2 index.html 삭제 (필요하지 않음)
rm -f /var/www/html/index.html

# apache mod ssl 활성화
dnf install -y mod_ssl >> "$log"

# apache mod expires 활성화
dnf install -y mod_expires >> "$log"

# apache rewrite 활성화
dnf install -y mod_rewrite >> "$log"

# FreePBX apache 설정 활성화
if [ ! "$nofpbx" ] ; then 
  # FreePBX용 Apache 설정 파일 생성
  cat <<EOF > /etc/httpd/conf.d/freepbx.conf
<VirtualHost *:80>
    DocumentRoot /var/www/html
    ServerName $fqdn
    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF
fi

# postfix 크기를 100MB로 설정
postconf -e message_size_limit=102400000

# 공격자에게 제공되는 정보를 줄이기 위해 expose_php 비활성화
sed -i 's/\(^expose_php = \).*/\1Off/' /etc/php.ini

# max_input_vars를 2000으로 설정
sed -i 's/;max_input_vars = 1000/max_input_vars = 2000/' /etc/php.ini

# 공격자에게 제공되는 정보를 줄이기 위해 ServerTokens와 ServerSignature 비활성화
sed -i 's/\(^ServerTokens \).*/\1Prod/' /etc/httpd/conf/httpd.conf
sed -i 's/\(^ServerSignature \).*/\1Off/' /etc/httpd/conf/httpd.conf

# pcre.jit를 0으로 설정
sed -i 's/;pcre.jit=1/pcre.jit=0/' /etc/php.ini

# httpd 재시작
systemctl restart httpd >> "$log"

setCurrentStep "패키지 홀드"

hold_packages

# logrotate 설정 업데이트
if grep -q '^#dateext' /etc/logrotate.conf; then
   message "logrotate.conf 설정"
   sed -i 's/^#dateext/dateext/' /etc/logrotate.conf
fi

# 권한 설정
chown -R asterisk:asterisk /var/www/html/

# 서명 새로고침
setCurrentStep "모듈 서명 새로고침."
count=1
if [ ! "$nofpbx" ]; then
  while [ $count -eq 1 ]; do
    set +e
    refresh_signatures
    exit_status=$?
    set -e
    if [ $exit_status -eq 0 ]; then
      break
    else
      log "명령 'fwconsole ma refreshsignatures'가 종료 상태 $exit_status로 실행에 실패했습니다. 백그라운드 작업으로 실행"
      refresh_signatures &
      log "나머지 스크립트 실행 계속"
      break
    fi
  done
fi

setCurrentStep "FreePBX 17 설치가 성공적으로 완료되었습니다."

############ 설치 후 검증 ############################################
# 설치 후 검증 명령
# 0이 아닌 종료 코드를 만났을 때 스크립트 자동 종료를 방지하기 위해 자동 스크립트 종료 비활성화
set +e
setCurrentStep "설치 후 검증"

check_services

check_php_version

if [ ! "$nofpbx" ] ; then
 check_freepbx
fi

check_asterisk

execution_time="$(($(date +%s) - start))"
message "전체 스크립트 실행 시간: $execution_time"
message "$host $kernel에 대한 FreePBX 17 설치 프로세스 완료"
message "FreePBX 커뮤니티 포럼에 참여하세요: https://community.freepbx.org/ ";

if [ ! "$nofpbx" ] ; then
  fwconsole motd
fi
