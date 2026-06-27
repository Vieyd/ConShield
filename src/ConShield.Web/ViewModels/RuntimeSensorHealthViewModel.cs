using ConShield.Application.Models;

namespace ConShield.Web.ViewModels;

public sealed class RuntimeSensorHealthViewModel
{
    public RuntimeSensorHealthSummary Summary { get; init; } =
        new(0, 0, 0, null);

    public IReadOnlyList<RuntimeSensorHealthRow> Sources { get; init; } =
        Array.Empty<RuntimeSensorHealthRow>();

    public string ActiveWindowLabel { get; init; } = "24h";
}
