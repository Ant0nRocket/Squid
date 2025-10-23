#!/bin/bash

echo "Обновление параметров SOCKS5 прокси..."

read -p "Новый IP адрес: " ADDR
read -p "Новый порт: " PORT
read -p "Новый пользователь: " USER
read -s -p "Новый пароль: " PASS
echo

# Обновляем переменные окружения
sudo tee /etc/systemd/system/squid.service.d/socks-auth.conf > /dev/null <<EOF
[Service]
Environment="ADDR=$ADDR"
Environment="PORT=$PORT"
Environment="SOCKS_USER=$USER"
Environment="SOCKS_PASS=$PASS"
EOF

# Генерируем новый конфиг
sudo systemctl daemon-reload
sudo /etc/squid/generate-socks-config.sh

# Перезапускаем squid
sudo systemctl restart squid

echo "Параметры прокси обновлены!"
echo "Новый сервер: $ADDR:$PORT"