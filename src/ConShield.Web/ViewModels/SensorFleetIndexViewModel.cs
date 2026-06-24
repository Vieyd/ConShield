namespace ConShield.Web.ViewModels;

public sealed class SensorFleetIndexViewModel
{
    public DateTime GeneratedAtUtc { get; init; }
    public IReadOnlyList<SensorFleetItemViewModel> Sensors { get; init; } = [];
}
