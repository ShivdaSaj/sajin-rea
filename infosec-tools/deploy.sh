#!/usr/bin/env bash
# Build and (re)deploy Infosec Tools on this Docker host behind its existing Traefik.
# Usage (from the infosec-tools folder):  ./deploy.sh
# Safe to rerun: keeps .env (and the admin password) and the /data volume.
set -euo pipefail
cd "$(dirname "$0")"
DOMAIN="${DOMAIN:-infosectools.sajinshivdas.online}"

command -v docker >/dev/null || { echo "docker is not installed"; exit 1; }
docker compose version >/dev/null || { echo "docker compose plugin is missing"; exit 1; }

if [ ! -f .env ]; then
  TRAEFIK=$(docker ps --format '{{.ID}} {{.Image}} {{.Names}}' | awk 'tolower($0) ~ /traefik/ {print $1; exit}')
  [ -n "$TRAEFIK" ] || { echo "No running Traefik container found. Set TRAEFIK_NETWORK/TRAEFIK_ENTRYPOINT/TRAEFIK_CERTRESOLVER in .env manually."; exit 1; }
  NET=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$TRAEFIK" | tr ' ' '\n' | grep -v '^$' | grep -v '^bridge$' | head -1)
  ARGS=$(docker inspect -f '{{join .Config.Cmd " "}} {{join .Args " "}}' "$TRAEFIK")
  # Look at Traefik's command line, and its static config file if there is one.
  CONF=$(docker exec "$TRAEFIK" sh -c 'cat /etc/traefik/traefik.yml /etc/traefik/traefik.yaml /etc/traefik/traefik.toml 2>/dev/null' || true)
  RESOLVER=$(printf '%s\n%s' "$ARGS" "$CONF" | grep -oE 'certificatesresolvers\.[A-Za-z0-9_-]+' | head -1 | cut -d. -f2)
  [ -n "$RESOLVER" ] || RESOLVER=$(printf '%s' "$CONF" | awk '/certificatesResolvers:/ {getline; gsub(/[ :]/,""); print; exit}')
  EP=$(printf '%s\n%s' "$ARGS" "$CONF" | grep -oiE 'entrypoints\.(websecure|https|web-secure|secure)' | head -1 | cut -d. -f2)
  [ -n "$EP" ] || EP=$(printf '%s' "$CONF" | grep -oE '^\s+(websecure|https):' | head -1 | tr -d ' :')
  PASS=$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 22)
  cat > .env <<ENV
DOMAIN=$DOMAIN
ADMIN_PASSWORD=$PASS
TRAEFIK_NETWORK=${NET:-proxy}
TRAEFIK_ENTRYPOINT=${EP:-websecure}
TRAEFIK_CERTRESOLVER=${RESOLVER:-letsencrypt}
ENV
  chmod 600 .env
  echo "Created .env (network=${NET:-proxy}, entrypoint=${EP:-websecure}, certresolver=${RESOLVER:-letsencrypt})."
  echo "Admin password (shown once, also stored in .env): $PASS"
fi

docker compose up -d --build
echo "Waiting for the container to report healthy..."
for i in $(seq 1 30); do
  s=$(docker inspect -f '{{.State.Health.Status}}' infosec-tools 2>/dev/null || echo starting)
  [ "$s" = healthy ] && break; sleep 2
done
docker compose ps
echo "Deployed. Open https://$DOMAIN (admin: https://$DOMAIN/admin)"
echo "If the certificate is not issued yet, check that the DNS A record for $DOMAIN points at this server."
