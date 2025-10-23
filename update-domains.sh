#!/bin/bash
# update-domains.sh

echo "Обновление списка доменов..."

# Проверяем наличие файла domains.txt
if [ ! -f "domains.txt" ]; then
    echo "Ошибка: Файл domains.txt не найден в текущей директории!"
    exit 1
fi

# Очищаем domains.txt: убираем комментарии, пустые строки, добавляем точки
TEMP_DOMAINS=$(mktemp)
grep -v '^#' domains.txt | grep -v '^$' | sed 's/^/./' > "$TEMP_DOMAINS"

# Проверяем, что есть валидные домены
if [ ! -s "$TEMP_DOMAINS" ]; then
    echo "Ошибка: В domains.txt не найдено валидных доменов!"
    rm "$TEMP_DOMAINS"
    exit 1
fi

# Копируем очищенный файл доменов
sudo cp "$TEMP_DOMAINS" /etc/squid/domains.list
sudo chown proxy:proxy /etc/squid/domains.list

# Удаляем временный файл
rm "$TEMP_DOMAINS"

DOMAIN_COUNT=$(wc -l < /etc/squid/domains.list)
echo "Домены обновлены! Загружено $DOMAIN_COUNT доменов."

# Перезапускаем Squid для применения изменений
echo "Перезапуск Squid..."
sudo systemctl restart squid

echo "Готово!"