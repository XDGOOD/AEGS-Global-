#!/usr/bin/env bash
set -euo pipefail

# Синхронный редеплой aegis_server на новый KDF (PBKDF2).
# Данные не мигрируются (ключ не хранится, только aegis_token) —
# скрипт просто безопасно перекатывает бинарник с бэкапом и откатом.
#
# ВАЖНО: сразу после (или до) запуска этого скрипта разошли всем
# пользователям новый aegis_client. Старый клиент (SHA256-ключ)
# после обновления сервера перестанет авторизовываться.

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${APP_DIR}/data"
DB_PATH="${DATA_DIR}/aegis.db"
BACKUP_DIR="${DATA_DIR}/backups"
CONTAINER_NAME="aegis_server"
IMAGE_NEW="aegis-server:new-kdf"
IMAGE_PREV_TAG="aegis-server:pre-kdf-rollback"

timestamp() { date +%Y%m%d_%H%M%S; }

echo "[1/7] Бэкап БД..."
mkdir -p "$BACKUP_DIR"
BACKUP_FILE="${BACKUP_DIR}/aegis_$(timestamp).db"
if command -v sqlite3 >/dev/null; then
    sqlite3 "$DB_PATH" ".backup '$BACKUP_FILE'"
else
    cp "$DB_PATH" "$BACKUP_FILE"
fi
echo "  -> $BACKUP_FILE"

echo "[2/7] Тегирую текущий образ как rollback-точку (если есть)..."
if docker image inspect aegis-server:latest >/dev/null 2>&1; then
    docker tag aegis-server:latest "$IMAGE_PREV_TAG"
fi

echo "[3/7] Собираю новый образ..."
docker build -f "${APP_DIR}/Dockerfile.aegis" -t "$IMAGE_NEW" "$APP_DIR"

echo "[4/7] Останавливаю текущий контейнер..."
docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true

echo "[5/7] Запускаю новый контейнер..."
docker run -d --name "$CONTAINER_NAME" \
    -p 50001:50001/udp \
    -v "$DATA_DIR":/app/data \
    --restart unless-stopped \
    "$IMAGE_NEW"

echo "[6/7] Проверка живости (10 сек)..."
sleep 10
if ! docker ps --filter "name=${CONTAINER_NAME}" --filter "status=running" | grep -q "$CONTAINER_NAME"; then
    echo "!!! Новый контейнер не поднялся, откатываюсь на предыдущий образ..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    if docker image inspect "$IMAGE_PREV_TAG" >/dev/null 2>&1; then
        docker run -d --name "$CONTAINER_NAME" \
            -p 50001:50001/udp \
            -v "$DATA_DIR":/app/data \
            --restart unless-stopped \
            "$IMAGE_PREV_TAG"
        echo "  -> откачено на $IMAGE_PREV_TAG. БД не трогали, бэкап на всякий: $BACKUP_FILE"
    else
        echo "  !!! rollback-образа нет, поднимай вручную из бэкапа $BACKUP_FILE"
    fi
    exit 1
fi

docker tag "$IMAGE_NEW" aegis-server:latest
echo "[7/7] Готово. Новый сервер работает: PBKDF2-KDF активен."
echo ""
echo "НЕ ЗАБУДЬ: разослать всем клиентам новый aegis_client (та же сборка,"
echo "что и сервер) — иначе их токены перестанут матчиться с ключом."
