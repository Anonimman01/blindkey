"""Константы протокола. Менять их = менять формат протокола (нужна новая версия)."""

PROTOCOL_VERSION = "v1"

# Длина мастер-секрета и производных ключей, байт.
MASTER_SECRET_LEN = 32
DERIVED_KEY_LEN = 32

# Соль HKDF: фиксированная, привязана к версии протокола.
HKDF_SALT = b"gatekeeper-hkdf-salt-v1"

# Метки контекста (параметр info в HKDF).
INFO_SIGN_PREFIX = "sign|epoch="

# Заголовки подписи запроса.
HEADER_CLIENT = "X-GK-Client"
HEADER_EPOCH = "X-GK-Epoch"
HEADER_TIME = "X-GK-Time"
HEADER_NONCE = "X-GK-Nonce"
HEADER_SIG = "X-GK-Sig"

# Допустимое расхождение часов клиента и шлюза, секунд.
MAX_CLOCK_SKEW_SECONDS = 30
