using ConShield.Application.Models;
using ConShield.Contracts.Models;

namespace ConShield.Application;

public interface IUserExceptionService
{
    Task<IReadOnlyList<UserExceptionDto>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<UserExceptionDto>> GetPageAsync(int skip, int take, CancellationToken cancellationToken = default);
    Task<int> CountAsync(CancellationToken cancellationToken = default);
    Task<UserExceptionDto?> GetByIdAsync(int id, CancellationToken cancellationToken = default);
    Task<UserExceptionDto> CreateAsync(UserExceptionCreateRequest request, CancellationToken cancellationToken = default);
    Task<UserExceptionDto?> UpdateAsync(UserExceptionUpdateRequest request, CancellationToken cancellationToken = default);
    Task<bool> DeleteAsync(int id, string? userName, CancellationToken cancellationToken = default);
}
