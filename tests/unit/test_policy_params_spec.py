"""B4: тесты-спецификация параметрических правил политики (кода ещё нет).

Эти тесты намеренно пропущены: они фиксируют договорённый контракт из
`docs/policy-params.md`, чтобы реализация началась с готовых проверок. Убрать `skip`
нужно вместе с реализацией, а не раньше.
"""
import pytest

pytestmark = pytest.mark.skip(reason="B4: спецификация до реализации — см. docs/policy-params.md")

BODY = b'{"chat_id":123,"text":"hi"}'


def test_rule_without_parameters_keeps_the_old_semantics():
    """`POST:sendMessage` без `?` разрешает любой chat_id (совместимость)."""


def test_rule_with_parameters_accepts_a_listed_value():
    """`POST:sendMessage?chat_id=123,456` разрешает 123 и 456."""


def test_rule_rejects_an_unlisted_value():
    """Значение вне списка — отказ deny_policy с reason=param_mismatch."""


def test_rule_rejects_a_missing_parameter():
    """Параметра нет в теле — отказ с reason=param_missing."""


def test_comparison_is_type_strict():
    """`chat_id=123` не совпадает с `"123"`: типы сравниваются строго."""


def test_non_json_body_is_rejected_when_the_rule_has_parameters():
    """Правило с параметрами и тело не JSON — отказ с reason=param_not_json, upstream не вызван."""


def test_parameters_rule_on_get_is_a_configuration_error():
    """У GET нет тела: правило с параметрами на GET запрещено при выпуске пакета."""


def test_param_denial_happens_before_approvals():
    """Отказ по параметрам не создаёт заявку и не расходует подтверждение оператора."""


def test_values_are_not_written_to_the_audit_log():
    """В журнал попадают только имена несовпавших параметров, не их значения."""
