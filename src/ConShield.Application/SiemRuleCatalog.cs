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
            RuleName = "Массовые изменения записей UserExceptions",
            Severity = EventSeverity.Critical,
            Description = "Правило выявляет подозрительную серию операций изменения или удаления исключений доступа.",
            ConditionText = "5 и более операций изменения/удаления",
            WindowText = "30 секунд",
            TriggerEntityText = "Пользователь, выполнивший операцию"
        },
        new SiemRuleDefinition
        {
            RuleCode = "CR-001",
            RuleName = "Повторные критические события с одного источника",
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
            ConditionText = "criticalCount >= 1",
            WindowText = "24 часа",
            TriggerEntityText = "Digest или reference контейнерного образа"
        },
        new SiemRuleDefinition
        {
            RuleCode = "POL-001",
            RuleName = "Блокировка контейнерного образа политикой",
            Severity = EventSeverity.Critical,
            Description = "Правило выявляет решения Container Policy Gate с результатом Block.",
            ConditionText = "decision == Block",
            WindowText = "24 часа",
            TriggerEntityText = "Policy + digest или reference контейнерного образа"
        },
        new SiemRuleDefinition
        {
            RuleCode = "RTE-001",
            RuleName = "Container runtime threat detected",
            Severity = EventSeverity.High,
            Description = "Правило выявляет подтвержденные Falco-compatible runtime события для контейнеров.",
            ConditionText = "mapped runtime event, correlate == true, severity High/Critical",
            WindowText = "10 минут",
            TriggerEntityText = "Container identity + mapping + process"
        },
        new SiemRuleDefinition
        {
            RuleCode = "LIFE-001",
            RuleName = "Sensor identity revoked",
            Severity = EventSeverity.Warning,
            Description = "Правило выявляет отзыв sensor identity как чувствительное lifecycle-действие.",
            ConditionText = "SourceSystem == conshield.sensor-lifecycle и ExternalEventType == sensor.revoked",
            WindowText = "24 часа",
            TriggerEntityText = "Публичный sensor id"
        },
        new SiemRuleDefinition
        {
            RuleCode = "LIFE-002",
            RuleName = "Repeated sensor credential lifecycle changes",
            Severity = EventSeverity.Warning,
            Description = "Правило выявляет повторные ротации или отзывы credentials одного sensor за короткий интервал.",
            ConditionText = "3 и более sensor.credential.rotated/sensor.credential.revoked для одного sensor",
            WindowText = "15 минут",
            TriggerEntityText = "Публичный sensor id"
        }
    ];
}
