"""Исключения проекта. Текст ошибок не должен содержать секретов."""


class GatekeeperError(Exception):
    """Базовое исключение проекта."""


class KdfError(GatekeeperError):
    """Неверные параметры при выводе ключа."""


class SigningError(GatekeeperError):
    """Ошибка при подписи или проверке запроса."""


class AuditError(GatekeeperError):
    """Ошибка журнала (повреждение, невозможность записи)."""


class PkiError(GatekeeperError):
    """Ошибка работы с сертификатами и ключами."""


class PolicyError(GatekeeperError):
    """Неверное правило политики клиента."""
