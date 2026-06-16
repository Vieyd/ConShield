using ConShield.Contracts.Enums;

namespace ConShield.Application.Models;

public sealed class SiemRuleDefinition
{
    public string RuleCode { get; init; } = string.Empty;
    public string RuleName { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public EventSeverity Severity { get; init; }
    public string ConditionText { get; init; } = string.Empty;
    public string WindowText { get; init; } = string.Empty;
    public string TriggerEntityText { get; init; } = string.Empty;
}
