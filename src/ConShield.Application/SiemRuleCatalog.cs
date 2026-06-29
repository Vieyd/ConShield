using ConShield.Application.Models;
using ConShield.Contracts.Enums;

namespace ConShield.Application;

public static class SiemRuleCatalog
{
    public static readonly IReadOnlyCollection<SiemRuleDefinition> Rules =
    [
        new SiemRuleDefinition
        {
            RuleCode = "BF-001",
            RuleName = "Повторные неуспешные попытки входа",
            Severity = EventSeverity.High,
            Description = "Правило выявляет признаки подбора пароля по одной учетной записи.",
            ConditionText = "3 и более неуспешных входа",
            WindowText = "2 минуты",
            TriggerEntityText = "Учетная запись пользователя"
        },
        new SiemRuleDefinition
        {
            RuleCode = "UE-001",
            RuleName = "Массовые изменения исключений доступа",
            Severity = EventSeverity.Critical,
            Description = "Правило выявляет подозрительную серию операций изменения или удаления исключений доступа.",
            ConditionText = "5 и более операций изменения/удаления",
            WindowText = "30 секунд",
            TriggerEntityText = "Пользователь, выполнивший операцию"
        },
        new SiemRuleDefinition
        {
            RuleCode = "CR-001",
            RuleName = "Повторные критические события от одного источника",
            Severity = EventSeverity.Critical,
            Description = "Правило выявляет повторение критических событий с одного источника и инициирует эскалацию.",
            ConditionText = "2 и более критических события",
            WindowText = "5 минут",
            TriggerEntityText = "IP-источник события"
        },
        new SiemRuleDefinition
        {
            RuleCode = "IMG-001",
            RuleName = "Критические уязвимости в контейнерном образе",
            Severity = EventSeverity.Critical,
            Description = "Правило выявляет результаты Trivy-сканирования контейнерного образа с критическими уязвимостями.",
            ConditionText = "критических уязвимостей >= 1",
            WindowText = "24 часа",
            TriggerEntityText = "Digest или reference контейнерного образа"
        },
        new SiemRuleDefinition
        {
            RuleCode = "POL-001",
            RuleName = "Блокировка контейнерного образа политикой",
            Severity = EventSeverity.Critical,
            Description = "Правило выявляет решения Container Policy Gate с результатом «блокировка».",
            ConditionText = "решение = блокировка",
            WindowText = "24 часа",
            TriggerEntityText = "Политика + digest/reference образа"
        },
        new SiemRuleDefinition
        {
            RuleCode = "RTE-001",
            RuleName = "Угроза во время выполнения контейнера",
            Severity = EventSeverity.High,
            Description = "Правило выявляет подтвержденные Falco-compatible runtime-события для контейнеров.",
            ConditionText = "сопоставленное runtime-событие, корреляция включена, критичность высокая/критическая",
            WindowText = "10 минут",
            TriggerEntityText = "Контейнер + сопоставление + процесс"
        },
        new SiemRuleDefinition
        {
            RuleCode = "LIFE-001",
            RuleName = "Отзыв идентификатора сенсора",
            Severity = EventSeverity.Warning,
            Description = "Правило выявляет отзыв идентификатора сенсора как чувствительное lifecycle-действие.",
            ConditionText = "система-источник = conshield.sensor-lifecycle и внешний тип события = sensor.revoked",
            WindowText = "24 часа",
            TriggerEntityText = "Публичный ID сенсора"
        },
        new SiemRuleDefinition
        {
            RuleCode = "LIFE-002",
            RuleName = "Повторные изменения учетных данных сенсора",
            Severity = EventSeverity.Warning,
            Description = "Правило выявляет повторные ротации или отзывы учетных данных одного сенсора за короткий интервал.",
            ConditionText = "3 и более событий sensor.credential.rotated/sensor.credential.revoked для одного сенсора",
            WindowText = "15 минут",
            TriggerEntityText = "Публичный ID сенсора"
        },
        new SiemRuleDefinition
        {
            RuleCode = "SENSOR-001",
            RuleName = "Неизвестный runtime-сенсор",
            Severity = EventSeverity.High,
            Description = "Правило выявляет runtime/Falco-события от источника, отсутствующего в реестре доверия сенсоров.",
            ConditionText = "trustStatus = Unknown",
            WindowText = "24 часа",
            TriggerEntityText = "SourceSystem runtime-события"
        },
        new SiemRuleDefinition
        {
            RuleCode = "SENSOR-002",
            RuleName = "Отозванный или отключенный runtime-сенсор",
            Severity = EventSeverity.Critical,
            Description = "Правило выявляет runtime/Falco-события от источника со статусом Revoked или Disabled.",
            ConditionText = "trustStatus = Revoked или Disabled",
            WindowText = "24 часа",
            TriggerEntityText = "SensorId или SourceSystem"
        }
    ];
}
