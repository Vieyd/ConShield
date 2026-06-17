using Microsoft.Extensions.Options;

namespace ConShield.MongoProjection;

public sealed class MongoProjectionOptionsValidator : IValidateOptions<MongoProjectionOptions>
{
    public ValidateOptionsResult Validate(string? name, MongoProjectionOptions options)
    {
        var errors = new List<string>();

        if (options.Enabled && string.IsNullOrWhiteSpace(options.ConnectionString))
            errors.Add("ConnectionString is required when MongoProjection is enabled.");
        if (!string.IsNullOrWhiteSpace(options.ConnectionString) && options.ConnectionString.Any(char.IsControl))
            errors.Add("ConnectionString contains invalid characters.");

        ValidateName(options.DatabaseName, nameof(options.DatabaseName), errors);
        ValidateName(options.CollectionName, nameof(options.CollectionName), errors);

        if (options.RetentionDays is < 1 or > 365)
            errors.Add("RetentionDays must be between 1 and 365.");
        if (options.ConnectTimeoutSeconds is < 1 or > 60)
            errors.Add("ConnectTimeoutSeconds must be between 1 and 60.");
        if (options.OperationTimeoutSeconds is < 1 or > 60)
            errors.Add("OperationTimeoutSeconds must be between 1 and 60.");
        if (options.MaxDocumentBytes is < 4096 or > 1048576)
            errors.Add("MaxDocumentBytes must be between 4096 and 1048576.");

        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }

    private static void ValidateName(string? value, string optionName, ICollection<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 64)
        {
            errors.Add($"{optionName} is required and must be at most 64 characters.");
            return;
        }

        if (value.Any(ch => char.IsControl(ch) || !(char.IsAsciiLetterOrDigit(ch) || ch is '_' or '-')))
            errors.Add($"{optionName} may contain only letters, digits, underscore, and hyphen.");
    }
}
