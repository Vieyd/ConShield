namespace ConShield.Contracts.Enums;

public enum SecurityEventType
{
    LoginSuccess = 0,
    LoginFailure = 1,
    AccessDenied = 2,
    UserExceptionCreated = 3,
    UserExceptionUpdated = 4,
    UserExceptionDeleted = 5,
    CorrelationAlert = 6,
    IncidentCreated = 7,
    IncidentUpdated = 8,
    ExternalEvent = 9
}
