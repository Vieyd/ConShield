using ConShield.Data.Entities;

namespace ConShield.Web.ViewModels;

public class SecurityEventIndexViewModel
{
    public SecurityEventFilterViewModel Filter { get; set; } = new();
    public IReadOnlyList<SecurityEventEntry> Items { get; set; } = [];
    public PagingViewModel Paging { get; set; } = new();
}
