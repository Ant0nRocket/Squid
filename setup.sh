# Создаем основной конфиг Squid 6 - исправленный для версии 6.13
echo "Создание конфигурации Squid 6..."
sudo tee /etc/squid/squid.conf > /dev/null <<EOF
# Squid 6.13 Configuration
# Transparent Proxy with SOCKS5 support

# Basic settings
http_port 3128 transparent
forwarded_for delete

# Отключаем иконки чтобы избежать ошибок
icon_directory /nonexistent

# Security
tls_outgoing_options cafile=/etc/ssl/certs/ca-certificates.crt

# Disable caching for transparent proxy
cache deny all

# Access Control Lists
acl local_net src $LOCAL_NET
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT

# ACL для внутренних запросов Squid
acl localhost src 127.0.0.1/32
acl localhost src ::1/128

# Domains for SOCKS routing
acl socks_domains dstdomain "/etc/squid/domains.list"

# SOCKS5 upstream proxy - ВСЕ В ОДНОЙ СТРОКЕ!
cache_peer $ADDR parent $PORT 0 proxy-only login=$USER:$PASS connect-timeout=5 connect-fail-limit=3 name=socks_peer

# Access control for SOCKS
cache_peer_access socks_peer allow socks_domains
cache_peer_access socks_peer deny all

# Routing rules
never_direct allow socks_domains
always_direct deny socks_domains

# HTTP access rules - разрешаем localhost для внутренних нужд Squid
http_access allow localhost
http_access allow local_net socks_domains
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow local_net
http_access deny all

# Logging (minimal)
access_log daemon:/var/log/squid/access.log
cache_log /var/log/squid/cache.log

# Shutdown timeout
shutdown_lifetime 5 seconds
EOF