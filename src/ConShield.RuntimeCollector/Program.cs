using ConShield.RuntimeCollector;

var result = await RuntimeCollectorApp.RunAsync(args, Console.In, Console.Out, Console.Error, CancellationToken.None);
return (int)result;
