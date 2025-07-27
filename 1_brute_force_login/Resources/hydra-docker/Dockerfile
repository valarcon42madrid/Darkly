FROM kalilinux/kali-rolling

# Instala Hydra
RUN apt update && \
    apt install -y hydra && \
    apt clean

# Copia diccionarios locales al contenedor
COPY rockyou.txt /usr/share/wordlists/rockyou.txt
COPY users.txt /usr/share/wordlists/users.txt

ENTRYPOINT ["hydra"]

