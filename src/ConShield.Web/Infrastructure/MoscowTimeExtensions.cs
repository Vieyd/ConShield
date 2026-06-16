using System.Runtime.InteropServices;

namespace ConShield.Web.Infrastructure;

public static class MoscowTimeExtensions
{
    private static readonly TimeZoneInfo MoscowTimeZone = ResolveMoscowTimeZone();

    public static DateTime ToMoscowTime(this DateTime utcDateTime)
    {
        var normalized = utcDateTime.Kind == DateTimeKind.Unspecified
            ? DateTime.SpecifyKind(utcDateTime, DateTimeKind.Utc)
            : utcDateTime.ToUniversalTime();

        return TimeZoneInfo.ConvertTimeFromUtc(normalized, MoscowTimeZone);
    }

    public static DateTime ToMoscowLocal(this DateTime utcDateTime)
        => utcDateTime.ToMoscowTime();

    public static DateTime? ToMoscowLocal(this DateTime? utcDateTime)
        => utcDateTime.HasValue ? utcDateTime.Value.ToMoscowTime() : null;

    public static string ToMoscowDisplay(this DateTime utcDateTime)
        => utcDateTime.ToMoscowTime().ToString("dd.MM.yyyy HH:mm:ss");

    public static string ToMoscowDisplay(this DateTime? utcDateTime)
        => utcDateTime.HasValue ? utcDateTime.Value.ToMoscowDisplay() : "—";

    public static DateTime FromMoscowLocal(DateTime localDateTime)
    {
        var unspecified = DateTime.SpecifyKind(localDateTime, DateTimeKind.Unspecified);
        return TimeZoneInfo.ConvertTimeToUtc(unspecified, MoscowTimeZone);
    }

    private static TimeZoneInfo ResolveMoscowTimeZone()
    {
        var candidates = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? new[] { "Russian Standard Time" }
            : new[] { "Europe/Moscow" };

        foreach (var candidate in candidates)
        {
            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById(candidate);
            }
            catch (TimeZoneNotFoundException)
            {
            }
            catch (InvalidTimeZoneException)
            {
            }
        }

        return TimeZoneInfo.CreateCustomTimeZone(
            id: "MoscowCustom",
            baseUtcOffset: TimeSpan.FromHours(3),
            displayName: "GMT+03:00 Moscow",
            standardDisplayName: "Moscow"
        );
    }
}
