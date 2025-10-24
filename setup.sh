#!/bin/bash

set -e  # Прерывать выполнение при ошибках

echo "=== Настройка Squid 6.13 transparent proxy ==="

# Функция для безопасного ввода пароля
read_password() {
    local prompt="$1"
    local password
    while true; do
        read -s -p "$prompt" password
        echo
        if [ -n "$password" ]; then
            break
        else
            echo "Пароль не может быть пустым. Попробуйте снова."
        fi
    done
    echo -n "$password"
}

# Функция для валидации CIDR сети
validate_network() {
    local network="$1"
    if [[ ! $network =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 1
    fi
    
    local ip=$(echo "$network" | cut -d'/' -f1)
    local mask=$(echo "$network" | cut -d'/' -f2)
    
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
    if [ "$i1" -gt 255 ] || [ "$i2" -gt 255 ] || [ "$i3" -gt 255 ] || [ "$i4" -gt 255 ]; then
        return 1
    fi
    
    if [ "$mask" -lt 0 ] || [ "$mask" -gt 32 ]; then
        return 1
    fi
    
    return 0
}

# Проверяем наличие файла domains.txt
if [ ! -f "domains.txt" ]; then
    echo "Ошибка: Файл domains.txt не найден в текущей директории!"
    echo "Убедитесь, что domains.txt находится в той же папке, что и setup.sh"
    exit 1
fi

# Проверяем версию Ubuntu
echo "Проверка версии Ubuntu..."
UBUNTU_VERSION=$(lsb_release -rs)
echo "Обнаружена Ubuntu $UBUNTU_VERSION"

if [[ "$UBUNTU_VERSION" != "22.04" && "$UBUNTU_VERSION" != "24.04" ]]; then
    echo "ВНИМАНИЕ: Squid 6.13 рекомендуется для Ubuntu 22.04/24.04"
    echo "Текущая версия: $UBUNTU_VERSION"
    read -p "Продолжить установку? (y/N): " CONTINUE
    if [[ ! $CONTINUE =~ ^[Yy]$ ]]; then
        echo "Установка отменена."
        exit 1
    fi
fi

# Запрашиваем данные у пользователя
echo
echo "Введите данные SOCKS5 прокси:"
read -p "IP адрес сервера [185.58.115.51]: " ADDR
ADDR=${ADDR:-185.58.115.51}

read -p "Порт [42379]: " PORT
PORT=${PORT:-42379}

read -p "Имя пользователя [proxy_user]: " USER
USER=${USER:-proxy_user}

PASS=$(read_password "Пароль: ")

# Запрашиваем локальную сеть
echo
echo "Настройка локальной сети для доступа к прокси:"
while true; do
    read -p "Локальная сеть в формате CIDR [192.168.1.0/24]: " LOCAL_NET
    LOCAL_NET=${LOCAL_NET:-192.168.1.0/24}
    
    if validate_network "$LOCAL_NET"; then
        break
    else
        echo "Ошибка: Неверный формат сети. Используйте формат CIDR (например: 192.168.1.0/24)"
    fi
done

# Показываем введенные данные (без пароля)
echo
echo "Проверьте введенные данные:"
echo "Сервер: $ADDR:$PORT"
echo "Пользователь: $USER"
echo "Пароль: ********"
echo "Локальная сеть: $LOCAL_NET"
echo "Файл доменов: domains.txt ($(wc -l < domains.txt) строк)"
echo

read -p "Все верно? (y/N): " CONFIRM
if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
    echo "Настройка отменена."
    exit 1
fi

echo
echo "Настройка Squid proxy..."

# Обновляем пакеты
echo "Обновление пакетов..."
sudo apt update

# Устанавливаем Squid 6 (в Ubuntu 22.04/24.04 это версия по умолчанию)
echo "Установка Squid 6..."
sudo apt install -y squid iptables-persistent netfilter-persistent

# Проверяем версию Squid
echo "Проверка версии Squid..."
SQUID_VERSION=$(squid -v | grep Version | awk '{print $4}')
echo "Установлен Squid $SQUID_VERSION"

# Включаем IP forwarding
echo "Проверка IP forwarding..."
CURRENT_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$CURRENT_FORWARD" != "1" ]; then
    echo "Включение net.ipv4.ip_forward=1..."
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
    echo "IP forwarding включен"
else
    echo "IP forwarding уже включен"
fi

# Обрабатываем файл доменов
echo "Обработка файла доменов..."

# Создаем временный файл для очищенных доменов
TEMP_DOMAINS=$(mktemp)

# Очищаем domains.txt: убираем комментарии, пустые строки, добавляем точки
echo "Очистка доменов из domains.txt..."
grep -v '^#' domains.txt | grep -v '^$' | sed 's/^/./' > "$TEMP_DOMAINS"

# Проверяем, что есть валидные домены
if [ ! -s "$TEMP_DOMAINS" ]; then
    echo "Ошибка: В domains.txt не найдено валидных доменов!"
    rm "$TEMP_DOMAINS"
    exit 1
fi

# Копируем очищенный файл доменов
sudo cp "$TEMP_DOMAINS" /etc/squid/domains.list

# Устанавливаем права на файл доменов
sudo chown proxy:proxy /etc/squid/domains.list
sudo chmod 644 /etc/squid/domains.list

# Удаляем временный файл
rm "$TEMP_DOMAINS"

# Показываем статистику
DOMAIN_COUNT=$(wc -l < /etc/squid/domains.list)
echo "Обработано доменов: $DOMAIN_COUNT"

# Показываем первые 10 доменов для проверки
echo
echo "Первые 10 доменов из списка:"
head -10 /etc/squid/domains.list

# Создаем основной конфиг Squid 6
echo "Создание конфигурации Squid 6..."
sudo tee /etc/squid/squid.conf > /dev/null <<EOF
# Squid 6.13 Configuration
# Transparent Proxy with SOCKS5 support

# Basic settings
http_port 3128 transparent
dns_v4_first on
via off
forwarded_for delete

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

# Domains for SOCKS routing
acl socks_domains dstdomain "/etc/squid/domains.list"

# SOCKS5 upstream proxy
cache_peer $ADDR parent $PORT 0 \\
    proxy-only \\
    login=$USER:$PASS \\
    connect-timeout=5 \\
    connect-fail-limit=3 \\
    name=socks_peer \\
    socksversion=5

# Access control for SOCKS
cache_peer_access socks_peer allow socks_domains
cache_peer_access socks_peer deny all

# Routing rules
never_direct allow socks_domains
always_direct deny socks_domains

# HTTP access rules
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

# Устанавливаем правильные права на конфиг
sudo chown proxy:proxy /etc/squid/squid.conf
sudo chmod 644 /etc/squid/squid.conf

# Создаем директории для логов
echo "Настройка логов..."
sudo mkdir -p /var/log/squid
sudo chown -R proxy:proxy /var/log/squid

# Настройка iptables для transparent proxy
echo
echo "Настройка iptables..."

# Определяем сетевой интерфейс
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$INTERFACE" ]; then
    echo "Ошибка: Не удалось определить сетевой интерфейс"
    exit 1
fi
echo "Используется интерфейс: $INTERFACE"

# Очищаем старые правила
echo "Очистка старых правил iptables..."
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -F

# Перенаправляем HTTP и HTTPS трафик на Squid
echo "Добавление правил для HTTP (порт 80)..."
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 80 -j REDIRECT --to-port 3128

echo "Добавление правил для HTTPS (порт 443)..."
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 443 -j REDIRECT --to-port 3128

# Маскарадинг для выхода в интернет
echo "Добавление правил маскарадинга..."
sudo iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE

# Сохраняем правила
echo "Сохранение правил iptables..."
sudo netfilter-persistent save

# Проверяем конфигурацию Squid
echo "Проверка конфигурации Squid..."
if ! sudo squid -k parse; then
    echo "Ошибка в конфигурации Squid!"
    echo "Проверьте файл /etc/squid/squid.conf"
    exit 1
fi

# Инициализируем кеш (даже если он отключен, Squid требует структуру)
echo "Инициализация структуры Squid..."
sudo squid -z

# Перезапускаем Squid
echo "Запуск Squid..."
sudo systemctl enable squid
sudo systemctl restart squid

# Ждем запуска
sleep 3

# Проверяем статус
echo "Проверка статуса Squid..."
if ! sudo systemctl is-active --quiet squid; then
    echo "Ошибка: Squid не запустился"
    sudo systemctl status squid --no-pager -l
    echo "Логи:"
    sudo tail -20 /var/log/squid/cache.log || echo "Логи недоступны"
    exit 1
fi

echo
echo "=== Настройка завершена успешно! ==="
echo
echo "Информация о системе:"
echo "  Ubuntu: $UBUNTU_VERSION"
echo "  Squid: $SQUID_VERSION"
echo "  Интерфейс: $INTERFACE"
echo "  Локальная сеть: $LOCAL_NET"
echo "  Домены для SOCKS: $DOMAIN_COUNT"
echo
echo "Сетевые настройки:"
echo "  IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
echo
echo "Правила iptables:"
sudo iptables -t nat -L PREROUTING -n --line-numbers
echo
echo "Статус Squid:"
sudo systemctl status squid --no-pager --lines=10

# Тестирование
echo
echo "Для тестирования выполните на клиенте:"
echo "curl -I http://google.com"
echo "curl -I https://google.com"
echo
echo "Домены из списка будут идти через SOCKS прокси"
echo "Остальной трафик - напрямую"