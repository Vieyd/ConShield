using System.Text;
using ConShield.ContainerPolicy;

namespace ConShield.Tests;

public class ContainerPolicyTests
{
    [Fact]
    public void ValidPolicy_LoadsAndComputesSha256()
    {
        var result = Load(ValidPolicy());

        Assert.True(result.Success, result.Error);
        Assert.Equal("container-baseline", result.Policy!.PolicyId);
        Assert.Matches("^[0-9a-f]{64}$", result.Policy.PolicySha256);
    }

    [Theory]
    [InlineData("""[]""")]
    [InlineData("""{"schemaVersion":2,"policyId":"p","version":"1","thresholds":{},"deniedImages":[]}""")]
    [InlineData("""{"schemaVersion":1,"version":"1","thresholds":{},"deniedImages":[]}""")]
    [InlineData("""{"schemaVersion":1,"policyId":"p","version":"1","thresholds":{"criticalBlock":0},"deniedImages":[]}""")]
    [InlineData("""{"schemaVersion":1,"policyId":"p","version":"1","thresholds":{"criticalBlock":-1},"deniedImages":[]}""")]
    [InlineData("""{"schemaVersion":1,"policyId":"p","version":"1","thresholds":{"highWarn":5,"highBlock":3},"deniedImages":[]}""")]
    [InlineData("""{"schemaVersion":1,"policyId":"p","version":"1","thresholds":{},"deniedImages":["repo/app:1","REPO/APP:1"]}""")]
    [InlineData("""{"schemaVersion":1,"policyId":"p","version":"1","thresholds":{},"deniedImages":[],"extra":true}""")]
    public void InvalidPolicy_IsRejected(string json)
    {
        var result = Load(json);

        Assert.False(result.Success);
        Assert.NotEmpty(result.Error!);
    }

    [Fact]
    public void OversizedPolicy_IsRejected()
    {
        var result = new ContainerPolicyLoader().Load(Encoding.UTF8.GetBytes(new string(' ', ContainerPolicyLoader.MaxPolicyBytes + 1)));

        Assert.False(result.Success);
    }

    [Fact]
    public void DeniedImage_BlocksBeforeThresholds()
    {
        var policy = Load(ValidPolicy(deniedImages: """["repo/app:latest"]""")).Policy!;
        var result = Evaluate(policy, new ContainerImageScanSummary { ImageReference = "Repo/App:Latest", TotalCount = 0 });

        Assert.Equal(ContainerPolicyDecision.Block, result.Decision);
        Assert.Contains(ContainerPolicyReasonCodes.ImageDenied, result.ReasonCodes);
    }

    [Fact]
    public void CriticalHighAndTotalThresholds_BlockWithStableReasons()
    {
        var policy = Load(ValidPolicy()).Policy!;
        var result = Evaluate(policy, new ContainerImageScanSummary
        {
            ImageReference = "repo/app:1",
            CriticalCount = 1,
            HighCount = 10,
            TotalCount = 100
        });

        Assert.Equal(ContainerPolicyDecision.Block, result.Decision);
        Assert.Equal([
            ContainerPolicyReasonCodes.CriticalThresholdReached,
            ContainerPolicyReasonCodes.HighBlockThresholdReached,
            ContainerPolicyReasonCodes.TotalBlockThresholdReached
        ], result.ReasonCodes);
    }

    [Fact]
    public void WarningThresholds_Warn()
    {
        var policy = Load(ValidPolicy()).Policy!;
        var result = Evaluate(policy, new ContainerImageScanSummary
        {
            ImageReference = "repo/app:1",
            UnknownCount = 1,
            MediumCount = 10,
            HighCount = 1,
            TotalCount = 12
        });

        Assert.Equal(ContainerPolicyDecision.Warn, result.Decision);
        Assert.Equal([
            ContainerPolicyReasonCodes.HighWarningThresholdReached,
            ContainerPolicyReasonCodes.MediumWarningThresholdReached,
            ContainerPolicyReasonCodes.UnknownWarningThresholdReached
        ], result.ReasonCodes);
    }

    [Fact]
    public void WithinPolicy_Allows()
    {
        var policy = Load(ValidPolicy()).Policy!;
        var result = Evaluate(policy, new ContainerImageScanSummary
        {
            ImageReference = "repo/app:1",
            LowCount = 1,
            TotalCount = 1
        });

        Assert.Equal(ContainerPolicyDecision.Allow, result.Decision);
        Assert.Equal([ContainerPolicyReasonCodes.WithinPolicy], result.ReasonCodes);
    }

    [Fact]
    public void DigestIdentity_IsPreferred()
    {
        var policy = Load(ValidPolicy()).Policy!;
        var result = Evaluate(policy, new ContainerImageScanSummary
        {
            ImageReference = "repo/app:1",
            ImageDigest = "repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            TotalCount = 0
        });

        Assert.Equal("repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", result.TriggerIdentity);
    }

    [Fact]
    public void InvalidSummary_FailsClosed()
    {
        var policy = Load(ValidPolicy()).Policy!;
        var result = new ContainerPolicyEvaluator().Evaluate(policy, new ContainerImageScanSummary { ImageReference = "repo/app:1", CriticalCount = -1 });

        Assert.False(result.Success);
    }

    private static ContainerPolicyEvaluation Evaluate(ContainerPolicyDocument policy, ContainerImageScanSummary summary)
    {
        var result = new ContainerPolicyEvaluator().Evaluate(policy, summary);
        Assert.True(result.Success, result.Error);
        return result.Evaluation!;
    }

    private static ContainerPolicyLoadResult Load(string json)
    {
        return new ContainerPolicyLoader().Load(Encoding.UTF8.GetBytes(json));
    }

    private static string ValidPolicy(string deniedImages = "[]")
    {
        return $$"""
        {
          "schemaVersion": 1,
          "policyId": "container-baseline",
          "version": "1.0.0",
          "thresholds": {
            "criticalBlock": 1,
            "highBlock": 10,
            "totalBlock": 100,
            "highWarn": 1,
            "mediumWarn": 10,
            "unknownWarn": 1
          },
          "deniedImages": {{deniedImages}}
        }
        """;
    }
}
