namespace ConShield.Web.ViewModels;

public sealed class DemoUserDiagnosticsViewModel
{
    public string Environment { get; set; } = string.Empty;
    public int ConfiguredDemoUserCount { get; set; }
    public List<DemoUserDiagnosticsUserViewModel> Users { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public string SecretSafety { get; set; } = "Passwords and configuration values are intentionally not returned.";
}

public sealed class DemoUserDiagnosticsUserViewModel
{
    public string UserName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public bool HasPassword { get; set; }
}
