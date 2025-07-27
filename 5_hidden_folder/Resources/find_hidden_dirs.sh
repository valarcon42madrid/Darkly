#!/bin/bash

BASE_URL="http://172.20.10.12/.hidden/"
DOWNLOAD_DIR="./.hidden_dump"

mkdir -p "$DOWNLOAD_DIR"

function download_recursive() {
    local url="$1"
    local target_dir="$2"

    echo "📂 Descargando: $url"

    mkdir -p "$target_dir"

    # Descargar HTML del directorio
    html=$(curl -s "$url")

    # Extraer enlaces (carpetas o archivos)
    links=$(echo "$html" | grep -oP '(?<=href=")[^"]+' | grep -vE '^(\?|/)' | grep -v '^index.html' | grep -v '^\.\./')

    for link in $links; do
        if [[ "$link" == */ ]]; then
            # Es una subcarpeta → llamada recursiva
            download_recursive "$url$link" "$target_dir/$link"
        else
            # Es un archivo → descargarlo
            echo "📥 Archivo: $url$link"
            curl -s -o "$target_dir/$link" "$url$link"
        fi
    done
}

download_recursive "$BASE_URL" "$DOWNLOAD_DIR"



