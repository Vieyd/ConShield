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
        }
    ];
}
