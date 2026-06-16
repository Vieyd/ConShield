namespace ConShield.Application.Models;

public sealed class ExternalSecurityEventValidationResult
{
    public bool IsValid => Errors.Count == 0;
    public Dictionary<string, string[]> Errors { get; } = new(StringComparer.OrdinalIgnoreCase);

    public void Add(string field, string message)
    {
        if (!Errors.TryGetValue(field, out var existing))
        {
            Errors[field] = [message];
            return;
        }

        Errors[field] = existing.Concat([message]).ToArray();
    }
}
