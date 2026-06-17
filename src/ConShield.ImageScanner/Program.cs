namespace ConShield.ImageScanner;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cts.Cancel();
        };

        var exitCode = await ImageScannerApp.RunAsync(args, Console.Out, Console.Error, cts.Token);
        return (int)exitCode;
    }
}
