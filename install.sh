#!/bin/bash

#########################################
# 轻量化邮件服务器一键部署脚本 v13.0 终极修复版
# 技术栈: Postfix + Dovecot + Postfixadmin + Gophish(MySQL) + MySQL
# 系统要求: Debian 11/12
# 特性: Gophish使用MySQL后端，完整密码日志输出
#########################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 配置变量
HOSTNAME=""
DOMAIN=""
MYSQL_ROOT_PASS=""
MYSQL_MAIL_PASS=""
MYSQL_GOPHISH_PASS=""
POSTFIXADMIN_SETUP_PASS=""
ADMIN_EMAIL=""
IP_ADDRESS=""
GOPHISH_ADMIN_PASS=""
GOPHISH_PASSWORD_LINE=""
GOPHISH_PID=""

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本必须以root权限运行"
        exit 1
    fi
}

# 检查系统版本
check_system() {
    if ! grep -qE "debian|Debian" /etc/os-release; then
        log_error "此脚本仅支持Debian系统"
        exit 1
    fi
}

# 收集配置信息
collect_config() {
    echo -e "${BLUE}=== 配置信息收集 ===${NC}"
    
    # 获取默认IP
    DEFAULT_IP=$(ip route get 1 2>/dev/null | awk '/src/ {print $(NF-2); exit} END {if (!NR) exit 1}' || hostname -I | awk '{print $1}')
    
    echo -n "请输入服务器IP地址 [$DEFAULT_IP]: "
    read IP_ADDRESS
    IP_ADDRESS=${IP_ADDRESS:-$DEFAULT_IP}
    
    echo -n "请输入邮件域名 (例如: example.com): "
    read HOSTNAME0
    while [[ -z "$HOSTNAME0" ]]; do
        log_error "域名不能为空"
        echo -n "请输入邮件域名: "
        read HOSTNAME0
    done
    HOSTNAME=$(echo "mail.$HOSTNAME0")

    DOMAIN=$(echo $HOSTNAME | cut -d. -f2-)
    log_info "主域名设置为: $DOMAIN"
    
    ADMIN_EMAIL="admin@$HOSTNAME0"
 
    
    # 生成随机密码
    MYSQL_ROOT_PASS=$(openssl rand -hex 12)
    MYSQL_MAIL_PASS=$(openssl rand -hex 12)
    MYSQL_GOPHISH_PASS=$(openssl rand -hex 12)
    POSTFIXADMIN_SETUP_PASS=$(openssl rand -hex 12)
    
    echo ""
    log_info "配置收集完成，开始安装..."
    sleep 2
}

# 更新系统
update_system() {
    log_info "更新系统包..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq
    apt-get install -y -qq wget curl git vim net-tools unzip
}

# 设置主机名
setup_hostname() {
    log_info "配置主机名..."
    hostnamectl set-hostname $HOSTNAME
    
    if ! grep -q "$IP_ADDRESS $HOSTNAME" /etc/hosts; then
        echo "$IP_ADDRESS $HOSTNAME" >> /etc/hosts
    fi
}

# 安装并配置MySQL - 修复版
install_mysql() {
    log_info "检查MySQL状态..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    # 检查MySQL是否已安装
    MYSQL_INSTALLED=false
    MYSQL_HAS_PASSWORD=false
    EXISTING_ROOT_PASS=""
    
    if command -v mysql &> /dev/null; then
        MYSQL_INSTALLED=true
        log_info "检测到MySQL已安装"
        
        # 测试是否需要密码
        if ! mysql -u root -e "SELECT 1" 2>/dev/null; then
            MYSQL_HAS_PASSWORD=true
            log_warn "MySQL root用户已设置密码"
            
            echo ""
            echo -e "${YELLOW}检测到MySQL已安装且设置了root密码${NC}"
            echo "请选择处理方式:"
            echo "1) 输入现有root密码继续"
            echo "2) 完全重置MySQL（删除所有数据）"
            echo -n "请选择 [1/2]: "
            read MYSQL_CHOICE
            
            case $MYSQL_CHOICE in
                1)
                    echo -n "请输入MySQL root密码: "
                    read -s EXISTING_ROOT_PASS
                    echo ""
                    
                    # 验证密码
                    if ! mysql -u root -p"$EXISTING_ROOT_PASS" -e "SELECT 1" 2>/dev/null; then
                        log_error "密码错误，退出安装"
                        exit 1
                    fi
                    
                    log_info "密码验证成功"
                    MYSQL_ROOT_PASS=$EXISTING_ROOT_PASS
                    ;;
                2)
                    log_warn "将完全重置MySQL..."
                    
                    # 停止服务
                    systemctl stop mariadb 2>/dev/null || true
                    killall -9 mysqld 2>/dev/null || true
                    sleep 3
                    
                    # 删除数据目录
                    rm -rf /var/lib/mysql/*
                    rm -rf /etc/mysql/mariadb.conf.d/99-remote.cnf
                    
                    # 重新初始化
                    mysql_install_db --user=mysql --datadir=/var/lib/mysql
                    chown -R mysql:mysql /var/lib/mysql
                    
                    # 启动服务
                    systemctl start mariadb
                    sleep 3
                    ;;
                *)
                    log_error "无效选择"
                    exit 1
                    ;;
            esac
        fi
    else
        # 安装MySQL
        log_info "安装MySQL..."
        apt-get install -y -qq mariadb-server mariadb-client
    fi
    
    # 配置MySQL允许远程访问
    log_info "配置MySQL远程访问..."
    cat > /etc/mysql/mariadb.conf.d/99-remote.cnf <<EOF
[mysqld]
bind-address = 0.0.0.0
skip-name-resolve
max_connections = 500
EOF
    
    # 重启服务
    systemctl restart mariadb
    sleep 3
    
    # 配置数据库和用户
    log_info "配置数据库和用户..."
    
    # 根据是否有密码选择连接方式
    if [ "$MYSQL_HAS_PASSWORD" = true ]; then
        MYSQL_CMD="mysql -u root -p$MYSQL_ROOT_PASS"
    else
        MYSQL_CMD="mysql -u root"
    fi
    
    $MYSQL_CMD <<EOF
-- 设置/更新root密码
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASS';

-- 创建允许任何IP访问的root用户
DROP USER IF EXISTS 'root'@'%';
CREATE USER 'root'@'%' IDENTIFIED BY '$MYSQL_ROOT_PASS';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- 删除匿名用户和test数据库
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;

-- 创建数据库
CREATE DATABASE IF NOT EXISTS postfixadmin CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS gophish CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 删除旧用户
DROP USER IF EXISTS 'postfix'@'localhost';
DROP USER IF EXISTS 'postfix'@'127.0.0.1';
DROP USER IF EXISTS 'postfix'@'%';
DROP USER IF EXISTS 'postfixadmin'@'localhost';
DROP USER IF EXISTS 'postfixadmin'@'127.0.0.1';
DROP USER IF EXISTS 'postfixadmin'@'%';
DROP USER IF EXISTS 'gophish'@'localhost';
DROP USER IF EXISTS 'gophish'@'127.0.0.1';
DROP USER IF EXISTS 'gophish'@'%';

-- 创建用户（本地、127.0.0.1和远程）
CREATE USER 'postfix'@'localhost' IDENTIFIED BY '$MYSQL_MAIL_PASS';
CREATE USER 'postfix'@'127.0.0.1' IDENTIFIED BY '$MYSQL_MAIL_PASS';
CREATE USER 'postfix'@'%' IDENTIFIED BY '$MYSQL_MAIL_PASS';

CREATE USER 'postfixadmin'@'localhost' IDENTIFIED BY '$MYSQL_MAIL_PASS';
CREATE USER 'postfixadmin'@'127.0.0.1' IDENTIFIED BY '$MYSQL_MAIL_PASS';
CREATE USER 'postfixadmin'@'%' IDENTIFIED BY '$MYSQL_MAIL_PASS';

CREATE USER 'gophish'@'localhost' IDENTIFIED BY '$MYSQL_GOPHISH_PASS';
CREATE USER 'gophish'@'127.0.0.1' IDENTIFIED BY '$MYSQL_GOPHISH_PASS';
CREATE USER 'gophish'@'%' IDENTIFIED BY '$MYSQL_GOPHISH_PASS';

-- 授权
GRANT ALL PRIVILEGES ON postfixadmin.* TO 'postfixadmin'@'localhost';
GRANT ALL PRIVILEGES ON postfixadmin.* TO 'postfixadmin'@'127.0.0.1';
GRANT ALL PRIVILEGES ON postfixadmin.* TO 'postfixadmin'@'%';

GRANT SELECT ON postfixadmin.* TO 'postfix'@'localhost';
GRANT SELECT ON postfixadmin.* TO 'postfix'@'127.0.0.1';
GRANT SELECT ON postfixadmin.* TO 'postfix'@'%';

GRANT ALL PRIVILEGES ON gophish.* TO 'gophish'@'localhost';
GRANT ALL PRIVILEGES ON gophish.* TO 'gophish'@'127.0.0.1';
GRANT ALL PRIVILEGES ON gophish.* TO 'gophish'@'%';

FLUSH PRIVILEGES;
EOF
    
    # 验证gophish用户连接
    log_info "验证数据库连接..."
    if mysql -u gophish -p$MYSQL_GOPHISH_PASS -h 127.0.0.1 gophish -e "SELECT 1" 2>/dev/null; then
        log_info "Gophish数据库连接成功"
    else
        log_warn "Gophish数据库连接测试失败，尝试修复..."
    fi
    
    systemctl restart mariadb
    systemctl enable mariadb
    
    log_info "MySQL配置完成"
}

# 安装PHP和Nginx
install_php_nginx() {
    log_info "安装PHP和Nginx..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq nginx php php-fpm php-mysql php-mbstring php-imap php-json php-curl \
        php-zip php-gd php-xml php-intl
    
    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    
    systemctl start php${PHP_VERSION}-fpm
    systemctl enable php${PHP_VERSION}-fpm
    systemctl start nginx
    systemctl enable nginx
    
    rm -f /etc/nginx/sites-enabled/default
    systemctl restart nginx
}

# 安装Postfixadmin
install_postfixadmin() {
    log_info "安装Postfixadmin..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    # 预配置
    echo "postfixadmin postfixadmin/setup-password password $POSTFIXADMIN_SETUP_PASS" | debconf-set-selections
    echo "postfixadmin postfixadmin/setup-password-confirm password $POSTFIXADMIN_SETUP_PASS" | debconf-set-selections
    echo "postfixadmin postfixadmin/mysql/admin-pass password $MYSQL_ROOT_PASS" | debconf-set-selections
    echo "postfixadmin postfixadmin/mysql/app-pass password $MYSQL_MAIL_PASS" | debconf-set-selections
    echo "postfixadmin postfixadmin/database-type select mysql" | debconf-set-selections
    echo "postfixadmin postfixadmin/dbconfig-install boolean true" | debconf-set-selections
    
    apt-get install -y -qq postfixadmin
    
    # 生成密码hash
    SETUP_HASH=$(php -r "echo password_hash('$POSTFIXADMIN_SETUP_PASS', PASSWORD_DEFAULT);")
    
    # 创建配置文件
    cat > /etc/postfixadmin/config.local.php << EOF
<?php
\$CONF['configured'] = true;
\$CONF['setup_password'] = '$SETUP_HASH';
\$CONF['database_type'] = 'mysqli';
\$CONF['database_host'] = 'localhost';
\$CONF['database_user'] = 'postfixadmin';
\$CONF['database_password'] = '$MYSQL_MAIL_PASS';
\$CONF['database_name'] = 'postfixadmin';
\$CONF['admin_email'] = '$ADMIN_EMAIL';
\$CONF['encrypt'] = 'md5crypt';
\$CONF['domain_path'] = 'YES';
\$CONF['domain_in_mailbox'] = 'NO';
?>
EOF
    
    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    
    # 配置Nginx
    cat > /etc/nginx/sites-available/postfixadmin << EOF
server {
    listen 8080;
    server_name _;
    root /usr/share/postfixadmin/public;
    index index.php index.html;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/postfixadmin /etc/nginx/sites-enabled/
    systemctl restart nginx
    
    log_info "Postfixadmin安装完成"
}

# 安装Postfix
install_postfix() {
    log_info "安装Postfix..."
    
    export DEBIAN_FRONTEND=noninteractive
    echo "postfix postfix/mailname string $HOSTNAME" | debconf-set-selections
    echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
    
    apt-get install -y -qq postfix postfix-mysql
    
    # 配置main.cf
    cat > /etc/postfix/main.cf <<EOF
myhostname = $HOSTNAME
mydomain = $DOMAIN
myorigin = \$mydomain
mydestination = localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf
virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf

smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination

smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls = yes
smtpd_tls_auth_only = no
smtp_tls_security_level = may
smtpd_tls_security_level = may

message_size_limit = 52428800
EOF

    # MySQL查询配置
    cat > /etc/postfix/mysql-virtual-mailbox-domains.cf <<EOF
user = postfix
password = $MYSQL_MAIL_PASS
hosts = 127.0.0.1
dbname = postfixadmin
query = SELECT domain FROM domain WHERE domain='%s' AND active = 1
EOF

    cat > /etc/postfix/mysql-virtual-mailbox-maps.cf <<EOF
user = postfix
password = $MYSQL_MAIL_PASS
hosts = 127.0.0.1
dbname = postfixadmin
query = SELECT maildir FROM mailbox WHERE username='%s' AND active = 1
EOF

    cat > /etc/postfix/mysql-virtual-alias-maps.cf <<EOF
user = postfix
password = $MYSQL_MAIL_PASS
hosts = 127.0.0.1
dbname = postfixadmin
query = SELECT goto FROM alias WHERE address='%s' AND active = 1
EOF

    chmod 640 /etc/postfix/mysql-*.cf
    chown root:postfix /etc/postfix/mysql-*.cf
    
    systemctl restart postfix
    systemctl enable postfix
}

# 安装Dovecot
install_dovecot() {
    log_info "安装Dovecot..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql
    
    groupadd -g 5000 vmail 2>/dev/null || true
    useradd -g vmail -u 5000 vmail -d /var/vmail -m 2>/dev/null || true
    
    # 配置Dovecot
    cat > /etc/dovecot/dovecot.conf <<EOF
protocols = imap pop3 lmtp
listen = *, ::
mail_location = maildir:/var/vmail/%d/%n/Maildir
mail_uid = vmail
mail_gid = vmail
first_valid_uid = 5000
last_valid_uid = 5000
auth_mechanisms = plain login

passdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf
}

userdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf
}

service auth {
    unix_listener /var/spool/postfix/private/auth {
        mode = 0660
        user = postfix
        group = postfix
    }
}

service lmtp {
    unix_listener /var/spool/postfix/private/dovecot-lmtp {
        mode = 0600
        user = postfix
        group = postfix
    }
}

ssl = no
disable_plaintext_auth = no
log_path = /var/log/dovecot.log
EOF

    # 配置Dovecot SQL
    cat > /etc/dovecot/dovecot-sql.conf <<EOF
driver = mysql
connect = host=127.0.0.1 dbname=postfixadmin user=postfix password=$MYSQL_MAIL_PASS
default_pass_scheme = MD5-CRYPT
password_query = SELECT password FROM mailbox WHERE username='%u' AND active='1'
user_query = SELECT maildir, 5000 AS uid, 5000 AS gid FROM mailbox WHERE username='%u' AND active='1'
EOF

    chmod 640 /etc/dovecot/dovecot-sql.conf
    chown root:dovecot /etc/dovecot/dovecot-sql.conf
    
    systemctl restart dovecot
    systemctl enable dovecot
}

# 安装Gophish（使用MySQL后端）- 修复版
install_gophish() {
    log_info "安装Gophish（MySQL版本）..."
    
    cd /opt
    
    # 清理旧文件
    systemctl stop gophish 2>/dev/null || true
    killall gophish 2>/dev/null || true
    sleep 2
    rm -rf gophish 2>/dev/null || true
    rm -f gophish*.zip 2>/dev/null || true
    
    # 下载Gophish
    log_info "下载Gophish..."
    wget --no-check-certificate \
        -O gophish-v0.12.1-linux-64bit.zip \
        "https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip"
    
    # 验证下载
    if [ ! -f "gophish-v0.12.1-linux-64bit.zip" ] || [ $(stat -c%s "gophish-v0.12.1-linux-64bit.zip") -lt 1000000 ]; then
        log_error "Gophish下载失败"
        exit 1
    fi
    
    # 解压
    unzip -q gophish-v0.12.1-linux-64bit.zip -d gophish
    cd gophish
    chmod +x gophish
    
    # 配置文件 - 使用MySQL（修复连接字符串格式）
    cat > config.json <<EOF
{
    "admin_server": {
        "listen_url": "0.0.0.0:3333",
        "use_tls": false
    },
    "phish_server": {
        "listen_url": "0.0.0.0:80",
        "use_tls": false
    },
    "db_name": "mysql",
    "db_path": "gophish:$MYSQL_GOPHISH_PASS@tcp(127.0.0.1:3306)/gophish?charset=utf8mb4&parseTime=True&loc=Local",
    "migrations_prefix": "db/db_",
    "contact_address": "$ADMIN_EMAIL",
    "logging": {
        "filename": "/var/log/gophish.log",
        "level": "info"
    }
}
EOF

    # 清理可能的旧SQLite数据库
    rm -f gophish.db
    
    # 创建日志文件
    touch /var/log/gophish.log
    chmod 666 /var/log/gophish.log
    
    # 首次初始化数据库结构（不获取密码）
    log_info "初始化Gophish数据库结构..."
    timeout 10 ./gophish > /tmp/gophish_init.log 2>&1 &
    INIT_PID=$!
    sleep 8
    kill $INIT_PID 2>/dev/null || true
    killall gophish 2>/dev/null || true
    
    # 创建systemd服务（不自动启动）
    cat > /etc/systemd/system/gophish.service <<EOF
[Unit]
Description=Gophish
After=network.target mysql.service

[Service]
Type=simple
WorkingDirectory=/opt/gophish
ExecStart=/opt/gophish/gophish
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable gophish
    
    # 清理
    rm -f /opt/gophish-v0.12.1-linux-64bit.zip
    
    log_info "Gophish安装完成（未启动，将在最后获取密码）"
}

# 配置防火墙
setup_firewall() {
    log_info "配置防火墙..."
    
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq ufw
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    ufw allow 22/tcp comment "SSH"
    ufw allow 25/tcp comment "SMTP"
    ufw allow 80/tcp comment "HTTP/Gophish"
    ufw allow 110/tcp comment "POP3"
    ufw allow 143/tcp comment "IMAP"
    ufw allow 465/tcp comment "SMTPS"
    ufw allow 587/tcp comment "Submission"
    ufw allow 993/tcp comment "IMAPS"
    ufw allow 995/tcp comment "POP3S"
    ufw allow 3306/tcp comment "MySQL"
    ufw allow 8080/tcp comment "Postfixadmin"
    ufw allow 3333/tcp comment "Gophish Admin"
    
    ufw --force enable
}

# 最终显示
final_display() {
    # 显示结果
    clear
    echo ""
    echo "=================================================="
    echo "           邮件服务器安装完成！"
    echo "=================================================="
    echo ""
    echo -e "${GREEN}【Postfixadmin】${NC}"
    echo "访问地址: http://$IP_ADDRESS:8080/login.php"
    echo "设置密码: $POSTFIXADMIN_SETUP_PASS"
    echo "管理员邮箱: $ADMIN_EMAIL"
    echo "管理员邮箱密码：$POSTFIXADMIN_SETUP_PASS"
    echo ""
    echo -e "${GREEN}【MySQL数据库】${NC}"
    echo "远程连接: mysql -h $IP_ADDRESS -u root -p"
    echo "Root密码: $MYSQL_ROOT_PASS"
    echo ""
}

# gophish初始化密码
get_gophish_password() {
    echo ""
    echo -e "${GREEN}【Gophish（MySQL后端）】${NC}"
    echo "访问地址: http://$IP_ADDRESS:3333"
    echo "用户名: admin"
    echo ""
    
    # 清理旧进程
    killall gophish 2>/dev/null || true
    sleep 2
    
    # 启动Gophish获取密码
    log_info "启动Gophish获取密码..."
    cd /opt/gophish
    rm -f /tmp/gophish_output.log
    nohup ./gophish > /tmp/gophish_output.log 2>&1 &
    GOPHISH_PID=$!
    
    # 等待启动
    sleep 10
    
    # 获取密码
    echo -e "${YELLOW}Gophish密码信息：${NC}"
    echo "=================================================="
    grep -a -i "password" /tmp/gophish_output.log | head -1
    echo "=================================================="
    echo ""
    echo "如果看不到密码，请执行: grep -a -i password /tmp/gophish_output.log"
    echo ""
}

save_config(){
    # 保存配置信息
    cat > /root/mail-server-info.txt <<EOF
==========================================================
            邮件服务器配置信息
==========================================================
生成时间: $(date)

【Web界面访问】
Postfixadmin管理: http://$IP_ADDRESS:8080/index.php
  配置密码: $POSTFIXADMIN_SETUP_PASS
  管理员邮箱用户：$ADMIN_EMAIL
  管理员邮箱密码：$POSTFIXADMIN_SETUP_PASS

Gophish管理: http://$IP_ADDRESS:3333
  查看密码: grep -a -i password /tmp/gophish_output.log

【MySQL数据库】
主机: $IP_ADDRESS
端口: 3306
Root密码: $MYSQL_ROOT_PASS
Postfix密码: $MYSQL_MAIL_PASS
Gophish数据库密码: $MYSQL_GOPHISH_PASS

【日志文件】
邮件日志: /var/log/mail.log
Gophish日志: /var/log/gophish.log
Dovecot日志: /var/log/dovecot.log

【DNS配置】
A记录: $HOSTNAME -> $IP_ADDRESS
MX记录: $DOMAIN -> $HOSTNAME (优先级10)
SPF记录: v=spf1 a mx ip4:$IP_ADDRESS ~all
==========================================================
EOF
    
    chmod 600 /root/mail-server-info.txt
    log_info "配置已保存到: /root/mail-server-info.txt"

}

# 主函数
main() {
    clear
    echo -e "${BLUE}"
    echo "=========================================="
    echo "  邮件服务器一键部署脚本 v13.1"
    echo "  Gophish使用MySQL后端"
    echo "=========================================="
    echo -e "${NC}"
    
    check_root
    check_system
    collect_config
    
    log_info "开始部署..."
    
    update_system
    setup_hostname
    install_mysql
    install_php_nginx
    install_postfixadmin
    install_postfix
    install_dovecot
    install_gophish
    setup_firewall
    
    postfixadmin_setup
    final_display
    get_gophish_password
    save_config
    echo ""
}

postfixadmin_setup(){
    sleep 3
    #初始化
    curl -X POST -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2' -H 'Accept-Encoding: gzip, deflate' -H "Referer: http://${IP_ADDRESS}:8080/setup.php" -H 'Content-Type: application/x-www-form-urlencoded' -H "Origin: http://${IP_ADDRESS}:8080" -H 'Priority: u=0, i' -H 'Upgrade-Insecure-Requests: 1' -d "setup_password=${POSTFIXADMIN_SETUP_PASS}&submit=setuppw" "http://${IP_ADDRESS}:8080/setup.php" --compressed

    sleep 3

    # 创建管理员邮箱
    curl -X POST \
  -H "Referer: http://${IP_ADDRESS}/setup.php" \
  -H "Origin: http://${IP_ADDRESS}:8080" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'Priority: u=0, i' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0' \
  -d "setup_password=${POSTFIXADMIN_SETUP_PASS}&username=${ADMIN_EMAIL//@/%40}&password=${POSTFIXADMIN_SETUP_PASS}&password2=${POSTFIXADMIN_SETUP_PASS}&submit=createadmin" \
  "http://${IP_ADDRESS}:8080/setup.php" --compressed

}





# 执行主函数
main "$@"


