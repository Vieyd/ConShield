namespace ConShield.ImageScanner;

public enum ExitCodes
{
    Success = 0,
    InvalidArguments = 2,
    TrivyUnavailable = 3,
    ScanFailed = 4,
    ReportParsingFailed = 5,
    ApiRejectedRequest = 6,
    TimeoutOrCancellation = 7
}
