namespace ConShield.Web.ViewModels;

public sealed class PagingViewModel
{
    public const int DefaultPageSize = 25;
    public const int MaxPageSize = 100;

    public int Page { get; init; } = 1;
    public int PageSize { get; init; } = DefaultPageSize;
    public int TotalCount { get; init; }

    public int TotalPages => Math.Max(1, (int)Math.Ceiling(TotalCount / (double)PageSize));
    public bool HasPreviousPage => Page > 1;
    public bool HasNextPage => Page < TotalPages;

    public static (int Page, int PageSize) Normalize(int? page, int? pageSize)
    {
        var normalizedPage = Math.Max(1, page ?? 1);
        var normalizedPageSize = Math.Clamp(pageSize ?? DefaultPageSize, 1, MaxPageSize);

        return (normalizedPage, normalizedPageSize);
    }

    public static int ClampPage(int page, int pageSize, int totalCount)
    {
        var totalPages = Math.Max(1, (int)Math.Ceiling(totalCount / (double)pageSize));
        return Math.Min(page, totalPages);
    }
}
