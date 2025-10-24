#!/bin/bash

set -e  # Прерывать выполнение при ошибках

echo "=== Настройка Squid 6 transparent proxy ==="

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
    echo -n "$password" | tr -d '\n\r\t'
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

# Дополнительная очистка пароля
PASS=$(echo -n "$PASS" | tr -d '\n\r\t' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

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

# Показываем введенные данные
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

# Устанавливаем Squid
echo "Установка Squid..."
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

# Создаем пустую директорию для иконок
echo "Создание директории для иконок..."
sudo mkdir -p /usr/share/squid/errors/en-US
sudo touch /usr/share/squid/errors/en-US/error.txt
sudo chown -R proxy:proxy /usr/share/squid/errors

# Обрабатываем файл доменов
echo "Обработка файла доменов..."

# Создаем временный файл для очищенных доменов
TEMP_DOMAINS=$(mktemp)

# Очищаем domains.txt
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

# Создаем основной конфиг Squid - минимальный и рабочий
echo "Создание конфигурации Squid..."
sudo tee /etc/squid/squid.conf > /dev/null <<EOF
# Basic settings
http_port 3128
http_port 3129 transparent

# Disable caching
cache deny all

# Access Control Lists
acl local_net src $LOCAL_NET
acl socks_domains dstdomain "/etc/squid/domains.list"

# SOCKS5 upstream proxy
cache_peer $ADDR parent $PORT 0 proxy-only login=$USER:$PASS name=socks_peer

# Access control
cache_peer_access socks_peer allow socks_domains
cache_peer_access socks_peer deny all#!/bin/bash

set -e  # Прерывать выполнение при ошибках

echo "=== Настройка Squid 6 transparent proxy ==="

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
    echo -n "$password" | tr -d '\n\r\t'
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

# Запрашиваем данные у пользователя
echo
echo "Введите данные HTTP прокси:"
read -p "IP адрес сервера [185.58.115.51]: " ADDR
ADDR=${ADDR:-185.58.115.51}

read -p "Порт [42379]: " PORT
PORT=${PORT:-42379}

read -p "Имя пользователя [proxy_user]: " USER
USER=${USER:-proxy_user}

PASS=$(read_password "Пароль: ")

# Дополнительная очистка пароля
PASS=$(echo -n "$PASS" | tr -d '\n\r\t' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

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

# Показываем введенные данные
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

# Устанавливаем Squid
echo "Установка Squid..."
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

# Очищаем domains.txt
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

# Создаем основной конфиг Squid - HTTP прокси + домены идут через прокси, остальное напрямую
echo "Создание конфигурации Squid..."
sudo tee /etc/squid/squid.conf > /dev/null <<EOF
# Basic settings
http_port 3128 transparent

# Disable caching
cache deny all

# Access Control Lists
acl local_net src $LOCAL_NET

# Домены для проксирования
acl proxy_domains dstdomain "/etc/squid/domains.list"

# HTTP upstream proxy для доменов из списка
cache_peer $ADDR parent $PORT 0 login=$USER:$PASS name=upstream_proxy

# Домены из списка идут через upstream прокси
cache_peer_access upstream_proxy allow proxy_domains
cache_peer_access upstream_proxy deny all

# Остальной трафик идет напрямую
never_direct allow proxy_domains
always_direct deny proxy_domains

# HTTP access
http_access allow proxy_domains
http_access allow local_net
http_access deny all

# Logging
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
EOF

# Проверяем что записалось в конфиг
echo "Проверка конфигурации..."
echo "=== Строка cache_peer ==="
sudo grep "cache_peer" /etc/squid/squid.conf
echo "=== Конец проверки ==="

# Устанавливаем правильные права на конфиг
sudo chown proxy:proxy /etc/squid/squid.conf
sudo chmod 644 /etc/squid/squid.conf

# Создаем директории для логов
echo "Настройка логов..."
sudo mkdir -p /var/log/squid
sudo chown -R proxy:proxy /var/log/squid

# Настройка iptables
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

# Маскарадинг
echo "Добавление правил маскарадинга..."
sudo iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE

# Сохраняем правила
echo "Сохранение правил iptables..."
sudo netfilter-persistent save

# Проверяем конфигурацию Squid
echo "Проверка конфигурации Squid..."
if sudo squid -k parse; then
    echo "✅ Конфигурация верна"
else
    echo "❌ Ошибка в конфигурации Squid!"
    exit 1
fi

# Инициализируем кеш
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
if sudo systemctl is-active --quiet squid; then
    echo "✅ Squid запущен успешно"
    
    echo
    echo "=== Настройка завершена успешно! ==="
    echo
    echo "Информация о системе:"
    echo "  Squid: $SQUID_VERSION"
    echo "  Интерфейс: $INTERFACE"
    echo "  Локальная сеть: $LOCAL_NET"
    echo "  Домены для прокси: $DOMAIN_COUNT"
    echo
    echo "Сетевые настройки:"
    echo "  IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
    echo
    echo "Правила iptables:"
    sudo iptables -t nat -L PREROUTING -n --line-numbers
    echo
    echo "Статус Squid:"
    sudo systemctl status squid --no-pager --lines=5

    echo
    echo "Для тестирования выполните на клиенте:"
    echo "curl -I https://youtube.com  # через прокси"
    echo "curl -I https://google.com   # напрямую"
    echo
    echo "Логи доступа:"
    echo "sudo tail -f /var/log/squid/access.log"
else
    echo "❌ Ошибка: Squid не запустился"
    echo "Логи Squid:"
    sudo journalctl -u squid.service -n 20 --no-pager
    exit 1
fi

# Routing
never_direct allow socks_domains

# HTTP access
http_access allow socks_domains
http_access allow local_net
http_access deny all

# Logging
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
EOF

# Проверяем что записалось в конфиг
echo "Проверка конфигурации..."
echo "=== Строка cache_peer ==="
sudo grep "cache_peer" /etc/squid/squid.conf
echo "=== Конец проверки ==="

# Устанавливаем правильные права на конфиг
sudo chown proxy:proxy /etc/squid/squid.conf
sudo chmod 644 /etc/squid/squid.conf

# Создаем директории для логов
echo "Настройка логов..."
sudo mkdir -p /var/log/squid
sudo chown -R proxy:proxy /var/log/squid

# Настройка iptables
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
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 80 -j REDIRECT --to-port 3129

echo "Добавление правил для HTTPS (порт 443)..."
sudo iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 443 -j REDIRECT --to-port 3129

# Маскарадинг
echo "Добавление правил маскарадинга..."
sudo iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE

# Сохраняем правила
echo "Сохранение правил iptables..."
sudo netfilter-persistent save

# Проверяем конфигурацию Squid
echo "Проверка конфигурации Squid..."
if sudo squid -k parse; then
    echo "✅ Конфигурация верна"
else
    echo "❌ Ошибка в конфигурации Squid!"
    exit 1
fi

# Инициализируем кеш
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
if sudo systemctl is-active --quiet squid; then
    echo "✅ Squid запущен успешно"
    
    echo
    echo "=== Настройка завершена успешно! ==="
    echo
    echo "Информация о системе:"
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
    sudo systemctl status squid --no-pager --lines=5

    echo
    echo "Для тестирования выполните на клиенте:"
    echo "curl -I https://youtube.com  # через SOCKS"
    echo "curl -I https://google.com   # напрямую"
else
    echo "❌ Ошибка: Squid не запустился"
    echo "Логи Squid:"
    sudo journalctl -u squid.service -n 20 --no-pager
    exit 1
fi