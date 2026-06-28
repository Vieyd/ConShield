namespace ConShield.Web.ViewModels;

public sealed class DemoWalkthroughViewModel
{
    public int SecurityEventsCount { get; init; }
    public int SiemAlertsCount { get; init; }
    public int IncidentsCount { get; init; }
    public int RuntimeSensorSourcesCount { get; init; }
    public DateTime? LatestRuntimeSensorLastSeenUtc { get; init; }

    public IReadOnlyList<DemoWalkthroughStepViewModel> Steps { get; init; } =
        Array.Empty<DemoWalkthroughStepViewModel>();

    public IReadOnlyList<DemoWalkthroughCommandViewModel> Commands { get; init; } =
        Array.Empty<DemoWalkthroughCommandViewModel>();
}

public sealed record DemoWalkthroughStepViewModel(
    int Number,
    string Name,
    string Purpose,
    string CommandOrLink,
    string? Controller,
    string? Action,
    string ExpectedResult);

public sealed record DemoWalkthroughCommandViewModel(
    string Name,
    string Command,
    string ExpectedResult);
