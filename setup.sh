#!/bin/bash

set -e  # Прерывать выполнение при ошибках

echo "=== Настройка Squid transparent proxy ==="

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
    echo "$password"
}

# Функция для валидации CIDR сети
validate_network() {
    local network="$1"
    if [[ ! $network =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 1
    fi
    
    # Проверяем корректность IP и маски
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

# Запрашиваем данные у пользователя
echo
echo "Введите данные SOCKS5 прокси:"
read -p "IP адрес сервера [185.58.115.51]: " ADDR
ADDR=${ADDR:-185.58.115.51}

read -p "Порт [42379]: " PORT
PORT=${PORT:-42379}

read -p "Имя пользователя [proxy_user]: " USER
USER=${USER:-proxy_user}

echo "Введите пароль:"
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

# Обновляем пакеты и устанавливаем необходимые
echo "Установка необходимых пакетов..."
sudo apt update
sudo apt install -y squid iptables-persistent netfilter-persistent

# Включаем IP forwarding если не включен
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

# Создаем файл с переменными окружения с правильным экранированием
echo "Создание файла с переменными окружения..."
sudo tee /etc/squid/socks-auth.env > /dev/null <<EOF
ADDR='$ADDR'
PORT='$PORT'
SOCKS_USER='$USER'
SOCKS_PASS='$PASS'
LOCAL_NET='$LOCAL_NET'
EOF

# Устанавливаем права на файл с переменными
sudo chown proxy:proxy /etc/squid/socks-auth.env
sudo chmod 600 /etc/squid/socks-auth.env

# Создаем скрипт для генерации конфига
sudo tee /etc/squid/generate-socks-config.sh > /dev/null <<'EOF'
#!/bin/bash
# Скрипт генерации конфигурации SOCKS peer

# Загружаем переменные из файла с проверкой
if [ -f /etc/squid/socks-auth.env ]; then
    # Безопасно загружаем переменные
    while IFS='=' read -r key value; do
        # Пропускаем комментарии и пустые строки
        [[ $key =~ ^[[:space:]]*# ]] && continue
        [[ -z $key ]] && continue
        
        # Убираем кавычки и лишние пробелы
        key=$(echo "$key" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        value=$(echo "$value" | sed "s/^[[:space:]]*['\"]//; s/['\"][[:space:]]*$//")
        
        # Экспортируем переменную
        export "$key"="$value"
    done < /etc/squid/socks-auth.env
fi

# Проверяем, что все переменные установлены
if [ -z "$SOCKS_USER" ] || [ -z "$SOCKS_PASS" ] || [ -z "$ADDR" ] || [ -z "$PORT" ] || [ -z "$LOCAL_NET" ]; then
    echo "Ошибка: Не все переменные окружения установлены"
    echo "SOCKS_USER: $SOCKS_USER"
    echo "ADDR: $ADDR" 
    echo "PORT: $PORT"
    echo "LOCAL_NET: $LOCAL_NET"
    exit 1
fi

# Генерируем конфигурационную строку
echo "cache_peer $ADDR parent $PORT 0 proxy-only=1 login=$SOCKS_USER:$SOCKS_PASS round-robin no-query connect-fail-limit=2 socks5=1 name=socks_proxy" > /etc/squid/socks-peer.conf

# Устанавливаем права
chown proxy:proxy /etc/squid/socks-peer.conf
chmod 600 /etc/squid/socks-peer.conf

echo "Конфигурация SOCKS peer обновлена: $ADDR:$PORT"
echo "Локальная сеть: $LOCAL_NET"
EOF

# Делаем скрипт исполняемым
sudo chmod +x /etc/squid/generate-socks-config.sh

# Запускаем генерацию конфига
echo "Генерация конфигурации SOCKS..."
sudo /etc/squid/generate-socks-config.sh

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

# Настройка iptables для transparent proxy
echo
echo "Настройка iptables..."

# Определяем сетевой интерфейс (может потребоваться изменить)
INTERFACE="enp0s3"

# Если интерфейс не существует, пытаемся определить автоматически
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "Автоматическое определение сетевого интерфейса..."
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$INTERFACE" ]; then
        echo "Ошибка: Не удалось определить сетевой интерфейс"
        exit 1
    fi
    echo "Используется интерфейс: $INTERFACE"
fi

# Очищаем старые правила
echo "Очистка старых правил iptables..."
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -F

# Перенаправляем HTTP трафик на Squid
echo "Добавление правил для HTTP (порт 80)..."
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 80 -j REDIRECT --to-port 3128

# Перенаправляем HTTPS трафик на Squid
echo "Добавление правил для HTTPS (порт 443)..."
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 443 -j REDIRECT --to-port 3128

# Маскарадинг для выхода в интернет
echo "Добавление правил маскарадинга..."
sudo iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE

# Сохраняем правила для persistence
echo "Сохранение правил iptables..."
sudo netfilter-persistent save

# Создаем основной конфиг Squid с динамической локальной сетью
echo "Создание основного конфига Squid..."
sudo tee /etc/squid/squid.conf > /dev/null <<EOF
# Базовые настройки transparent proxy
http_port 3128 transparent
visible_hostname ubuntu-vpc

# Кэширование не нужно для transparent
cache deny all

# ACL для локальной сети
acl local_net src $LOCAL_NET

# ACL для доменов из файла
acl socks_domains dstdomain "/etc/squid/domains.list"

# Настройка SOCKS для доменов из списка
include /etc/squid/socks-peer.conf

# Управление доступом к SOCKS proxy
cache_peer_access socks_proxy allow socks_domains
cache_peer_access socks_proxy deny all

# Правила маршрутизации
never_direct allow socks_domains
always_direct allow all

# Разрешаем доступ из локальной сети
http_access allow local_net

# Запрещаем всё остальное
http_access deny all
EOF

# Создаем systemd service для автоматической генерации конфига при перезапуске
sudo tee /etc/systemd/system/squid-config.service > /dev/null <<'EOF'
[Unit]
Description=Generate Squid SOCKS config
Before=squid.service

[Service]
Type=oneshot
ExecStart=/etc/squid/generate-socks-config.sh
RemainAfterExit=yes
User=root

[Install]
WantedBy=multi-user.target
EOF

# Включаем сервис генерации конфига
sudo systemctl enable squid-config.service

# Перезапускаем Squid
echo "Перезапуск Squid..."
sudo systemctl restart squid-config
sudo systemctl restart squid
sudo systemctl enable squid

echo
echo "=== Настройка завершена! ==="
echo "Установленные пакеты: squid, iptables-persistent"
echo "Созданные файлы:"
echo "  /etc/squid/squid.conf"
echo "  /etc/squid/socks-peer.conf"
echo "  /etc/squid/domains.list ($DOMAIN_COUNT доменов)"
echo "  /etc/squid/socks-auth.env"
echo "  /etc/squid/generate-socks-config.sh"
echo
echo "Сетевые настройки:"
echo "  net.ipv4.ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"
echo "  Интерфейс: $INTERFACE"
echo "  Локальная сеть: $LOCAL_NET"
echo
echo "Правила iptables:"
sudo iptables -t nat -L PREROUTING -n
echo
echo "Статус Squid:"
sudo systemctl status squid --no-pager -l