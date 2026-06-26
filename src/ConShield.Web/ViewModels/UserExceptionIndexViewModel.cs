using ConShield.Contracts.Models;

namespace ConShield.Web.ViewModels;

public sealed class UserExceptionIndexViewModel
{
    public IReadOnlyList<UserExceptionDto> Items { get; set; } = [];
    public PagingViewModel Paging { get; set; } = new();
}
