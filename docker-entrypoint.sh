#!/bin/sh
set -eu

app_user="app"
app_group="app"

chown_existing() {
    path="$1"
    if [ -e "$path" ] || [ -L "$path" ]; then
        chown "$app_user:$app_group" "$path"
    fi
}

prepare_data_dir() {
    dir="$1"
    db_file="$2"

    if [ -z "$dir" ]; then
        return
    fi

    mkdir -p "$dir"
    chown "$app_user:$app_group" "$dir"

    chown_existing "$db_file"
    chown_existing "$db_file-wal"
    chown_existing "$db_file-shm"
    chown_existing "$dir/config.json"
    chown_existing "$dir/known_hosts"
}

if [ "$(id -u)" = "0" ]; then
    # Previous images wrote persisted files as root; repair ownership before dropping privileges.
    db_path="${DEBIAN_UPDATER_DB_PATH:-/data/servers.db}"
    db_dir="$(dirname "$db_path")"

    if [ -d /data ]; then
        chown -R "$app_user:$app_group" /data
    fi
    prepare_data_dir "$db_dir" "$db_path"

    exec su-exec "$app_user:$app_group" "$@"
fi

exec "$@"
