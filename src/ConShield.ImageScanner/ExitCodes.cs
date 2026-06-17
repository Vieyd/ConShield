namespace ConShield.ImageScanner;

public enum ExitCodes
{
    Success = 0,
    InvalidArguments = 2,
    TrivyUnavailable = 3,
    ScanFailed = 4,
    ReportParsingFailed = 5,
    ApiRejectedRequest = 6,
    TimeoutOrCancellation = 7,
    WarningNotAccepted = 10,
    PolicyBlocked = 20,
    InvalidPolicy = 21,
    PolicyEvaluationFailed = 22,
    DockerUnavailable = 23,
    LaunchFailed = 24,
    LaunchTimeoutOrCancellation = 25
}
