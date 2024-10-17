#!/usr/bin/env bash
set -e
set -o pipefail

if [[ "$1" = 'create-oauth-app' && "$(id -u)" = '0' ]]; then
    exec gosu beenslab "${BASH_SOURCE[0]}" "$@"
fi

args=("${@:1}")
if [[ "${args[0]}" = 'create-oauth-app' ]]; then
    cd /opt/create-oauth-app/
    while true; do
        set +e
        echo "Run ${args[@]:1} with --expose-gc"
        node --expose-gc ./dist/index.js "${args[@]:1}"
        ret=$?
        set -e
        if test -e /tmp/docker-entrypoint-auto-restart.command; then
            echo "docker-entrypoint: process exited with exit code $ret" >&2
            echo "Restarting due to /tmp/docker-entrypoint-auto-restart.command" >&2
            sleep 1
            continue
        fi
        exit $ret
    done
fi

exec "${args[@]}"
