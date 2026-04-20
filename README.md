# opkssh-oidc

SSH-доступ к серверам через OIDC-аутентификацию с использованием PK Token (OpenPubKey) и короткоживущих SSH-сертификатов.

## Как это работает (PK Token)

Доверие строится не на общем CA-ключе, а на OIDC-провайдере. SSH-ключ криптографически привязан к OIDC-токену через `nonce`.

1. Клиент генерирует SSH-ключ.
2. Вычисляет `nonce = base64url(SHA256(ssh_public_key))`.
3. Запрашивает OIDC-токен с этим nonce — токен доказывает, что ключ принадлежит пользователю.
4. Создаёт self-signed SSH-сертификат (свой ключ = CA), встраивает OIDC-токен в `KeyId`.
5. Подключается к серверу по SSH.
6. На сервере `AuthorizedKeysCommand`:
   - Парсит сертификат, извлекает OIDC-токен из `KeyId`.
   - Проверяет подпись токена через JWKS.
   - Проверяет, что `nonce` в токене совпадает с `SHA256(публичный ключ сертификата)`.
   - Если всё верно — выдаёт `cert-authority <signing_key>`, sshd проверяет подпись сертификата.
7. NSS-модуль резолвит пользователя (UID/GID/home) через API.

**Результат**: никакого общего CA, никакого копирования ключей. Доверие полностью через OIDC.

---

## Подключение к серверу (клиент)

### Требования

- Go 1.21+
- `ssh-keygen` (предустановлен в macOS/Linux)

### Сборка

```bash
git clone https://github.com/mastervolkov/opkssh-oidc.git
cd opkssh-oidc
make
```

### Подключение

```bash
./qwe ssh <server-ip> --user alice --api-url http://<server-ip>:8080
```

Пример:

```bash
./qwe ssh 83.222.9.29 --user alice --api-url http://83.222.9.29:8080
```

Это автоматически:
- сгенерирует SSH-ключ (если нет);
- вычислит nonce из публичного ключа;
- получит OIDC-токен с привязкой к ключу;
- выпустит self-signed SSH-сертификат (15 мин TTL) с вшитым токеном;
- подключится по SSH.

Ключи и сертификаты сохраняются в `~/.qwe/`:
- `alice` — приватный ключ
- `alice.pub` — публичный ключ
- `alice-cert.pub` — SSH-сертификат
- `token.json` — кэш OIDC-токена

### Доступные пользователи (тестовые)

| Пользователь | Группы | Sudo |
|---|---|---|
| alice | cluster-1:admin, cluster-1:dev | да |
| bob | cluster-1:view | нет |

### Дополнительные команды

```bash
# Только получить токен (без SSH)
./qwe login --user alice --api-url http://<server-ip>:8080

# Только создать сертификат (без подключения)
./qwe ssh <server-ip> --user alice --api-url http://<server-ip>:8080 --cert-only

# Проверить сертификат
./qwe verify ~/.qwe/alice-cert.pub --api-url http://<server-ip>:8080
```

---

## Настройка сервера

### 1. Установить зависимости

```bash
apt-get update
apt-get install -y golang-go g++ libcurl4-openssl-dev
```

### 2. Собрать бинарник и NSS-модуль

```bash
git clone https://github.com/mastervolkov/opkssh-oidc.git
cd opkssh-oidc
make          # собирает бинарник qwe
make nss      # собирает libnss_oslogin.so
```

Или собрать бинарник на другой машине для Linux:

```bash
GOOS=linux GOARCH=amd64 make
```

### 3. Установить бинарник

```bash
cp qwe /usr/local/bin/qwe
chmod +x /usr/local/bin/qwe
```

### 4. Установить NSS-модуль

```bash
cp libnss_oslogin.so /lib/x86_64-linux-gnu/libnss_oslogin.so.2
ldconfig
```

Добавить `oslogin` в `/etc/nsswitch.conf`:

```
passwd: files oslogin
group:  files oslogin
```

Проверить:

```bash
# После запуска qwe serve
getent passwd alice
# alice:*:1001:1001:Alice Example:/home/alice:/bin/bash
```

### 5. Запустить API-сервер

Создать systemd-сервис `/etc/systemd/system/qwe.service`:

```ini
[Unit]
Description=QWE OIDC API Server
After=network.target

[Service]
ExecStart=/usr/local/bin/qwe serve
Environment=QWE_ISSUER=http://<server-ip>:8080
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now qwe
```

Проверить: `curl http://127.0.0.1:8080/`

### 6. Настроить sshd

Добавить в `/etc/ssh/sshd_config`:

```
AuthorizedKeysCommand /usr/local/bin/qwe --api-url http://<server-ip>:8080 auth-keys %u %k %t
AuthorizedKeysCommandUser nobody
```

```bash
systemctl restart ssh
```

> **Примечание**: В отличие от классической схемы с CA, серверу не нужны никакие ключевые файлы. Достаточно бинарника `qwe` и доступа к API.

### 7. Создать home-директории (опционально)

```bash
mkdir -p /home/alice /home/bob
chown 1001:1001 /home/alice
chown 1002:1002 /home/bob
```

Или включить автосоздание через PAM — добавить в `/etc/pam.d/sshd`:

```
session required pam_mkhomedir.so skel=/etc/skel umask=0022
```

---

## Проверка работоспособности

### На сервере

```bash
# API работает
curl http://127.0.0.1:8080/users?username=alice

# NSS резолвит пользователей
getent passwd alice

# auth-keys вручную (подставить base64 из сертификата)
sudo -u nobody /usr/local/bin/qwe --api-url http://<server-ip>:8080 auth-keys alice <base64> ssh-ed25519-cert-v01@openssh.com

# Логи sshd
journalctl -u ssh -f
```

### На клиенте

```bash
# Проверить сертификат
ssh-keygen -L -f ~/.qwe/alice-cert.pub

# Верифицировать токен и nonce-привязку
./qwe verify ~/.qwe/alice-cert.pub --api-url http://<server-ip>:8080

# Подключиться с debug
ssh -vvv -i ~/.qwe/alice -o CertificateFile=~/.qwe/alice-cert.pub alice@<server-ip>
```

---

## Архитектура

```
Клиент                          Сервер
──────                          ──────
qwe ssh <ip> --user alice
  │
  ├─ ssh-keygen (user key)       │
  ├─ nonce = SHA256(pubkey)      │
  │                              │
  ├─ POST /token {nonce} ──────► qwe serve (OIDC API :8080)
  │◄── id_token (nonce bound) ◄─┤
  │                              │
  ├─ self-sign cert              │
  │   (KeyId = user|jwt)         │
  │                              │
  ├─ SSH connect ──────────────► sshd
  │                              │ ├─ AuthorizedKeysCommand
  │                              │ │   └─ qwe auth-keys %u %k %t
  │                              │ │       ├─ parse cert from %k
  │                              │ │       ├─ extract OIDC token from KeyId
  │                              │ │       ├─ verify token via JWKS
  │                              │ │       ├─ verify nonce == SHA256(cert key)
  │                              │ │       └─ output: cert-authority <signing_key>
  │                              │ ├─ sshd verifies cert signature
  │                              │ └─ NSS (libnss_oslogin.so)
  │                              │       └─ GET /users?username=alice
  │◄── SSH session ◄────────────┤
```

## Структура проекта

```
cmd/qwe/main.go          CLI: serve, login, ssh, verify, auth-keys
internal/api/             OIDC API сервер (тестовые пользователи, /token, /jwks, /users, /groups)
internal/oidc/            JWT-токены: выпуск (EdDSA) и верификация через JWKS
internal/ssh/             SSH-ключи, self-signed сертификаты, PK Token верификация
nss/                      NSS-модуль (C++) для резолва пользователей через API
```
