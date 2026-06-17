using System.Security.Cryptography;
using System.Text;
using ConShield.ImageScanner;

namespace ConShield.Tests;

public class ImageScannerParserTests
{
    [Fact]
    public void EmptyResults_ProducesZeroCounts()
    {
        var summary = TrivyReportParser.Parse("""{"ArtifactName":"alpine:3.20","ArtifactType":"container_image","Results":[]}""", "trivy 1.0.0", "alpine:3.20");

        Assert.Equal(0, summary.TotalCount);
        Assert.Equal("alpine:3.20", summary.ImageReference);
    }

    [Fact]
    public void NullVulnerabilities_ProducesZeroCounts()
    {
        var summary = TrivyReportParser.Parse("""{"Results":[{"Target":"os","Vulnerabilities":null}]}""", "trivy", "image:test");

        Assert.Equal(0, summary.TotalCount);
        Assert.Equal(0, summary.AffectedTargetCount);
    }

    [Fact]
    public void AllSeverities_AreCountedAndFixAvailabilityIsComputed()
    {
        var json = """
        {
          "Metadata": { "RepoDigests": ["repo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] },
          "Results": [
            {
              "Target": "os",
              "Vulnerabilities": [
                { "VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1", "Severity": "LOW" },
                { "VulnerabilityID": "CVE-2", "PkgName": "b", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "MEDIUM" },
                { "VulnerabilityID": "CVE-3", "PkgName": "c", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH" },
                { "VulnerabilityID": "CVE-4", "PkgName": "d", "InstalledVersion": "1", "Severity": "CRITICAL" },
                { "VulnerabilityID": "CVE-5", "PkgName": "e", "InstalledVersion": "1", "Severity": "SOMETHING" }
              ]
            }
          ]
        }
        """;

        var summary = TrivyReportParser.Parse(json, "trivy", "repo/app:latest");

        Assert.Equal(1, summary.LowCount);
        Assert.Equal(1, summary.MediumCount);
        Assert.Equal(1, summary.HighCount);
        Assert.Equal(1, summary.CriticalCount);
        Assert.Equal(1, summary.UnknownCount);
        Assert.Equal(5, summary.TotalCount);
        Assert.Equal(2, summary.FixAvailableCount);
        Assert.Equal(1, summary.AffectedTargetCount);
    }

    [Fact]
    public void MultipleTargets_AreCounted()
    {
        var summary = TrivyReportParser.Parse("""
        {"Results":[
          {"Target":"os","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"a","InstalledVersion":"1","Severity":"HIGH"}]},
          {"Target":"app","Vulnerabilities":[{"VulnerabilityID":"CVE-2","PkgName":"b","InstalledVersion":"1","Severity":"CRITICAL"}]}
        ]}
        """, "trivy", "repo/app:latest");

        Assert.Equal(2, summary.TotalCount);
        Assert.Equal(2, summary.AffectedTargetCount);
    }

    [Fact]
    public void MalformedJson_IsRejected()
    {
        Assert.Throws<TrivyReportParseException>(() => TrivyReportParser.Parse("{", "trivy", "image:test"));
    }

    [Fact]
    public void MissingTopLevelFields_AreHandled()
    {
        var summary = TrivyReportParser.Parse("{}", "trivy", "fallback:tag");

        Assert.Equal("fallback:tag", summary.ImageReference);
        Assert.Equal(0, summary.TotalCount);
    }

    [Fact]
    public void OversizedReport_IsRejected()
    {
        var json = "{\"ArtifactName\":\"" + new string('a', ScannerConstants.MaxReportBytes) + "\"}";

        Assert.Throws<TrivyReportParseException>(() => TrivyReportParser.Parse(json, "trivy", "image:test"));
    }

    [Fact]
    public void ReportSha256_IsLowercaseHex()
    {
        const string json = """{"Results":[]}""";
        var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();

        var summary = TrivyReportParser.Parse(json, "trivy", "image:test");

        Assert.Equal(expected, summary.ReportSha256);
        Assert.Equal(64, summary.ReportSha256.Length);
        Assert.Equal(summary.ReportSha256, summary.ReportSha256.ToLowerInvariant());
    }

    [Fact]
    public void DigestSelection_UsesRepoDigest()
    {
        var report = new TrivyReport
        {
            Metadata = new TrivyMetadata
            {
                RepoDigests = ["repo/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
            }
        };

        Assert.Equal("repo/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", TrivyReportParser.SelectImageDigest(report));
    }
}
