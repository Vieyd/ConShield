using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace ConShield.EventPipeline;

public sealed class JsonlSecurityEventOutboxSink : ISecurityEventOutboxSink
{
    private static readonly SemaphoreSlim WriteLock = new(1, 1);
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly string _contentRootPath;
    private readonly SecurityEventOutboxOptions _options;

    public JsonlSecurityEventOutboxSink(string contentRootPath, IOptions<SecurityEventOutboxOptions> options)
    {
        _contentRootPath = Path.GetFullPath(contentRootPath);
        _options = options.Value;
    }

    public async Task<OutboxSinkResult> DeliverAsync(SecurityEventEnvelope envelope, CancellationToken cancellationToken)
    {
        if (!OutboxPathPolicy.IsSafeRelativePath(_options.JsonlRelativePath))
            return OutboxSinkResult.PermanentFailure("invalid_path", "JSONL path is not a safe relative path.");

        string fullPath;
        try
        {
            fullPath = ResolveContainedPath(_contentRootPath, _options.JsonlRelativePath);
        }
        catch (InvalidOperationException ex)
        {
            return OutboxSinkResult.PermanentFailure("invalid_path", ex.Message);
        }

        var line = JsonSerializer.Serialize(envelope, SerializerOptions);
        if (Encoding.UTF8.GetByteCount(line) > SecurityEventEnvelope.MaxPayloadBytes)
            return OutboxSinkResult.PermanentFailure("line_too_large", "Serialized envelope exceeded the maximum JSONL line size.");

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
            await WriteLock.WaitAsync(cancellationToken);
            try
            {
                await File.AppendAllTextAsync(fullPath, line + Environment.NewLine, Encoding.UTF8, cancellationToken);
            }
            finally
            {
                WriteLock.Release();
            }

            return OutboxSinkResult.Succeeded();
        }
        catch (OperationCanceledException)
        {
            return OutboxSinkResult.TransientFailure("cancelled", "JSONL write was cancelled.");
        }
        catch (UnauthorizedAccessException)
        {
            return OutboxSinkResult.TransientFailure("permission_denied", "JSONL sink path is not writable.");
        }
        catch (IOException)
        {
            return OutboxSinkResult.TransientFailure("io_error", "JSONL sink write failed.");
        }
    }

    internal static string ResolveContainedPath(string contentRootPath, string relativePath)
    {
        if (!OutboxPathPolicy.IsSafeRelativePath(relativePath))
            throw new InvalidOperationException("JSONL path must be relative and must not contain traversal segments.");

        var root = Path.GetFullPath(contentRootPath);
        var full = Path.GetFullPath(Path.Combine(root, relativePath));
        if (!full.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(full, root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("JSONL path must remain inside the content root.");
        }

        return full;
    }
}
