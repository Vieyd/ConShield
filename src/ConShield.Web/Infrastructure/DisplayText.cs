using System.Text.RegularExpressions;
using ConShield.Contracts.Enums;

namespace ConShield.Web.Infrastructure;

public static partial class DisplayText
{
    public static string Status(string? status) => status switch
    {
        "New" => "Новый",
        "Acknowledged" => "Подтверждено",
        "Closed" => "Закрыто",
        "InProgress" => "В работе",
        "Pending" => "Ожидает",
        "Processing" => "В обработке",
        "Delivered" => "Доставлено",
        "DeadLetter" => "Ошибка доставки",
        "Failed" => "Ошибка",
        "Unavailable" => "Недоступно",
        "Connected" => "Подключено",
        "Disconnected" => "Отключено",
        "Online" => "В сети",
        "Offline" => "Нет связи",
        "Never seen" => "Нет heartbeat",
        "Active" => "Активно",
        "Revoked" => "Отозвано",
        "Warning" => "Предупреждение",
        "Degraded" => "Требует внимания",
        "Attention" => "Требует внимания",
        "Needs attention" => "Требует внимания",
        "OK" => "Норма",
        "Eligible" => "Доступно для повтора",
        "RequiresReview" => "Требует проверки",
        "NotEligible" => "Недоступно для повтора",
        "Published" => "Опубликовано",
        "Requested" => "Запрошено",
        "unavailable" => "Недоступно",
        null or "" => "—",
        _ => status
    };

    public static string Severity(EventSeverity severity) => severity switch
    {
        EventSeverity.Critical => "Критический",
        EventSeverity.High => "Высокий",
        EventSeverity.Warning => "Предупреждение",
        EventSeverity.Info => "Информационный",
        _ => severity.ToString()
    };

    public static string EventType(SecurityEventType eventType) => eventType switch
    {
        SecurityEventType.LoginSuccess => "Успешный вход",
        SecurityEventType.LoginFailure => "Неуспешный вход",
        SecurityEventType.AccessDenied => "Отказ в доступе",
        SecurityEventType.UserExceptionCreated => "Создано исключение доступа",
        SecurityEventType.UserExceptionUpdated => "Изменено исключение доступа",
        SecurityEventType.UserExceptionDeleted => "Удалено исключение доступа",
        SecurityEventType.CorrelationAlert => "Оповещение корреляции",
        SecurityEventType.IncidentCreated => "Создан инцидент",
        SecurityEventType.IncidentUpdated => "Обновлен инцидент",
        SecurityEventType.ExternalEvent => "Внешнее событие",
        SecurityEventType.DeadLetterReplayRequested => "Запрошен повтор dead-letter",
        SecurityEventType.DeadLetterReplayPublished => "Dead-letter опубликован повторно",
        SecurityEventType.DeadLetterReplayRejected => "Повтор dead-letter отклонен",
        SecurityEventType.DeadLetterReplayFailed => "Повтор dead-letter не выполнен",
        _ => eventType.ToString()
    };

    public static string SeverityClass(EventSeverity severity) => severity switch
    {
        EventSeverity.Critical => "app-status-critical",
        EventSeverity.High => "app-status-high",
        EventSeverity.Warning => "app-status-warning",
        _ => "app-status-info"
    };

    public static string StatusClass(string? status)
    {
        var normalized = status?.Trim();
        return normalized switch
        {
            "OK" or "Ok" or "Connected" or "Delivered" or "Online" or "Active" or "Closed" or "Published" => "app-status-ok",
            "Critical" or "Failed" or "DeadLetter" or "Offline" or "Revoked" or "Ошибка" => "app-status-critical",
            "Warning" or "Degraded" or "Attention" or "Needs attention" or "NeedsAttention" or "RequiresReview" or "unavailable" or "Unavailable" => "app-status-attention",
            "New" or "Pending" or "Processing" or "InProgress" or "Requested" or "Never seen" => "app-status-info",
            _ => "app-status-neutral"
        };
    }

    public static string RuleName(string? ruleCode, string? fallback = null) => ruleCode switch
    {
        "BF-001" => "Повторные неуспешные попытки входа",
        "CR-001" => "Повторные критические события от одного источника",
        "IMG-001" => "Критические уязвимости в контейнерном образе",
        "LIFE-001" => "Отзыв идентификатора сенсора",
        "LIFE-002" => "Повторные изменения учетных данных сенсора",
        "POL-001" => "Блокировка контейнерного образа политикой",
        "RTE-001" => "Угроза во время выполнения контейнера",
        "UE-001" => "Массовые изменения исключений доступа",
        _ => string.IsNullOrWhiteSpace(fallback) ? ruleCode ?? "—" : fallback
    };

    public static string RuleCondition(string? ruleCode, string? fallback) => ruleCode switch
    {
        "IMG-001" => "критических уязвимостей >= 1",
        "POL-001" => "решение = блокировка",
        "RTE-001" => "сопоставленное runtime-событие, корреляция включена, критичность высокая/критическая",
        "LIFE-001" => "система-источник = conshield.sensor-lifecycle и внешний тип события = sensor.revoked",
        "LIFE-002" => "3 и более событий sensor.credential.rotated/sensor.credential.revoked для одного сенсора",
        _ => LocalizeTechnicalPhrase(fallback)
    };

    public static string RuleTriggerEntity(string? ruleCode, string? fallback) => ruleCode switch
    {
        "IMG-001" => "Digest или reference контейнерного образа",
        "POL-001" => "Политика + digest/reference образа",
        "RTE-001" => "Контейнер + сопоставление + процесс",
        "LIFE-001" or "LIFE-002" => "Публичный ID сенсора",
        _ => LocalizeTechnicalPhrase(fallback)
    };

    public static string RuleDescription(string? ruleCode, string? fallback = null) => ruleCode switch
    {
        "BF-001" => "Правило выявляет признаки подбора пароля по одной учетной записи.",
        "CR-001" => "Правило выявляет повторение критических событий от одного источника и инициирует эскалацию.",
        "IMG-001" => "Правило выявляет результаты Trivy-сканирования контейнерного образа с критическими уязвимостями.",
        "LIFE-001" => "Правило выявляет отзыв идентификатора сенсора как чувствительное lifecycle-действие.",
        "LIFE-002" => "Правило выявляет повторные ротации или отзывы учетных данных одного сенсора за короткий интервал.",
        "POL-001" => "Правило выявляет решения Container Policy Gate с результатом «блокировка».",
        "RTE-001" => "Правило выявляет подтвержденные Falco-compatible runtime-события для контейнеров.",
        "UE-001" => "Правило выявляет подозрительную серию операций изменения или удаления исключений доступа.",
        _ => LocalizeTechnicalPhrase(fallback)
    };

    public static string AlertDescription(string? ruleCode, string? description)
    {
        if (string.IsNullOrWhiteSpace(description))
            return "—";

        var text = description;
        text = text.Replace("Source events:", "Исходные события:", StringComparison.Ordinal);
        text = SourceEventRegex().Replace(text, "Исходное событие #${id}");

        if (string.Equals(ruleCode, "LIFE-001", StringComparison.Ordinal))
        {
            text = text.Replace("Sensor identity was revoked for sensor", "Идентификатор сенсора был отозван для сенсора", StringComparison.Ordinal);
            text = text.Replace("requestedBy=", "инициатор=", StringComparison.Ordinal);
            text = text.Replace("active credentials revoked", "активные учетные данные отозваны", StringComparison.Ordinal);
            text = text.Replace("credentials revoked", "учетные данные отозваны", StringComparison.Ordinal);
            return text;
        }

        if (string.Equals(ruleCode, "LIFE-002", StringComparison.Ordinal))
        {
            text = SensorCredentialLifecycleRegex().Replace(
                text,
                "Учетные данные сенсора изменялись ${count} раза за 15 минут для сенсора ${sensor}");
            return text;
        }

        if (string.Equals(ruleCode, "RTE-001", StringComparison.Ordinal))
        {
            text = RuntimeThreatRegex().Replace(
                text,
                "Обнаружена runtime-угроза: ${mapping} для ${identity}: правило=${rule}, процесс=${process}.");
            return text;
        }

        if (string.Equals(ruleCode, "POL-001", StringComparison.Ordinal))
        {
            text = text.Replace("Container policy", "Политика контейнеров", StringComparison.Ordinal);
            text = text.Replace("blocked image", "заблокировала образ", StringComparison.Ordinal);
            return text;
        }

        if (string.Equals(ruleCode, "IMG-001", StringComparison.Ordinal))
        {
            text = text.Replace("Trivy detected critical vulnerabilities in container image", "Trivy обнаружил критические уязвимости в контейнерном образе", StringComparison.Ordinal);
            return text;
        }

        return LocalizeTechnicalPhrase(text);
    }

    public static string IncidentTitle(string? title)
    {
        if (string.IsNullOrWhiteSpace(title))
            return "—";

        var match = IncidentTitleRegex().Match(title);
        if (!match.Success)
            return title;

        var code = match.Groups["code"].Value;
        return $"[{code}] {RuleName(code)}";
    }

    public static string IncidentNotes(string? notes)
    {
        if (string.IsNullOrWhiteSpace(notes))
            return "—";

        var codeMatch = RuleCodeRegex().Match(notes);
        var ruleCode = codeMatch.Success ? codeMatch.Groups["code"].Value : null;
        return AlertDescription(ruleCode, notes);
    }

    public static string SecuritySummaryStatus(string? status) => status switch
    {
        "NeedsAttention" => "Требует внимания",
        "NoData" => "Нет данных",
        "Ok" or "OK" => "Норма",
        _ => Status(status)
    };

    public static string RabbitMqError(string? errorCode)
    {
        if (string.IsNullOrWhiteSpace(errorCode))
            return "—";

        return errorCode switch
        {
            "rabbitmq_unavailable" => "RabbitMQ недоступен",
            "unavailable" => "Недоступно",
            _ when errorCode.Contains("RabbitMQ publish failed transiently", StringComparison.OrdinalIgnoreCase)
                => errorCode.Replace("RabbitMQ publish failed transiently.", "временный сбой публикации в RabbitMQ.", StringComparison.OrdinalIgnoreCase),
            _ => errorCode
        };
    }

    private static string LocalizeTechnicalPhrase(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "—";

        return value
            .Replace("credentials", "учетные данные", StringComparison.OrdinalIgnoreCase)
            .Replace("credential", "учетные данные", StringComparison.OrdinalIgnoreCase)
            .Replace("sensor", "сенсор", StringComparison.OrdinalIgnoreCase)
            .Replace("container", "контейнер", StringComparison.OrdinalIgnoreCase)
            .Replace("reference", "reference", StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"Source event #(?<id>\d+)", RegexOptions.CultureInvariant)]
    private static partial Regex SourceEventRegex();

    [GeneratedRegex(@"Sensor credential lifecycle changed (?<count>\d+) times in 15 minutes for sensor (?<sensor>[^.]+)", RegexOptions.CultureInvariant)]
    private static partial Regex SensorCredentialLifecycleRegex();

    [GeneratedRegex(@"Runtime threat (?<mapping>[^ ]+) detected for (?<identity>[^:]+): rule=(?<rule>[^,]+), process=(?<process>[^.]+)\.", RegexOptions.CultureInvariant)]
    private static partial Regex RuntimeThreatRegex();

    [GeneratedRegex(@"^\[(?<code>[A-Z]+-\d{3})\]\s*(?<name>.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex IncidentTitleRegex();

    [GeneratedRegex(@"(?<code>[A-Z]+-\d{3})", RegexOptions.CultureInvariant)]
    private static partial Regex RuleCodeRegex();
}
