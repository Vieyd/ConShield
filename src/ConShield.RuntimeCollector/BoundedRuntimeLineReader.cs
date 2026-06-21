using System.Runtime.CompilerServices;
using System.Text;

namespace ConShield.RuntimeCollector;

public static class BoundedRuntimeLineReader
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static IAsyncEnumerable<byte[]> ReadAsync(
        RuntimeCollectorOptions options,
        TextReader stdin,
        CancellationToken cancellationToken) =>
        options.Stdin
            ? ReadTextAsync(stdin, options.MaxLineBytes, cancellationToken)
            : ReadFileAsync(options.FilePath!, options.Follow, options.MaxLineBytes, cancellationToken);

    private static async IAsyncEnumerable<byte[]> ReadTextAsync(
        TextReader reader,
        int maxLineBytes,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var chars = new char[maxLineBytes];
        var one = new char[1];
        var length = 0;
        var oversized = false;

        while (await reader.ReadAsync(one.AsMemory(), cancellationToken) > 0)
        {
            if (one[0] == '\n')
            {
                yield return Encode(chars, length, oversized, maxLineBytes);
                length = 0;
                oversized = false;
                continue;
            }

            if (length < chars.Length)
                chars[length++] = one[0];
            else
                oversized = true;
        }

        if (length > 0 || oversized)
            yield return Encode(chars, length, oversized, maxLineBytes);
    }

    private static byte[] Encode(char[] chars, int length, bool oversized, int maxLineBytes)
    {
        if (length > 0 && chars[length - 1] == '\r')
            length--;
        if (oversized)
            return Oversized(maxLineBytes);

        try
        {
            var bytes = StrictUtf8.GetBytes(chars, 0, length);
            return bytes.Length <= maxLineBytes ? bytes : Oversized(maxLineBytes);
        }
        catch (EncoderFallbackException)
        {
            return [0xff];
        }
    }

    private static async IAsyncEnumerable<byte[]> ReadFileAsync(
        string path,
        bool follow,
        int maxLineBytes,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 8192,
            useAsync: true);
        var chunk = new byte[8192];
        var line = new byte[maxLineBytes];
        var lineLength = 0;
        var oversized = false;
        var lastWriteUtc = File.GetLastWriteTimeUtc(path);

        while (true)
        {
            var read = await stream.ReadAsync(chunk.AsMemory(), cancellationToken);
            if (read > 0)
            {
                for (var index = 0; index < read; index++)
                {
                    var value = chunk[index];
                    if (value == (byte)'\n')
                    {
                        var outputLength = lineLength > 0 && line[lineLength - 1] == (byte)'\r'
                            ? lineLength - 1
                            : lineLength;
                        yield return oversized ? Oversized(maxLineBytes) : line[..outputLength];
                        lineLength = 0;
                        oversized = false;
                    }
                    else if (lineLength < line.Length)
                    {
                        line[lineLength++] = value;
                    }
                    else
                    {
                        oversized = true;
                    }
                }

                lastWriteUtc = File.GetLastWriteTimeUtc(path);
                continue;
            }

            if (!follow)
            {
                if (lineLength > 0 || oversized)
                    yield return oversized ? Oversized(maxLineBytes) : line[..lineLength];
                yield break;
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            var info = new FileInfo(path);
            if (info.Length < stream.Position
                || (info.Length == stream.Position && info.LastWriteTimeUtc > lastWriteUtc))
            {
                stream.Position = 0;
                lineLength = 0;
                oversized = false;
            }
            lastWriteUtc = info.LastWriteTimeUtc;
        }
    }

    private static byte[] Oversized(int maxLineBytes) => new byte[maxLineBytes + 1];
}
