using ConShield.Application.Models;
using ConShield.Contracts.Enums;
using ConShield.Contracts.Models;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.SecurityEvents;
using ConShield.SecurityEvents.Models;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Application;

public class UserExceptionService : IUserExceptionService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ISecurityEventWriter _eventWriter;

    public UserExceptionService(ApplicationDbContext dbContext, ISecurityEventWriter eventWriter)
    {
        _dbContext = dbContext;
        _eventWriter = eventWriter;
    }

    public async Task<IReadOnlyList<UserExceptionDto>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.UserExceptions
            .OrderByDescending(x => x.CreatedAtUtc)
            .ThenByDescending(x => x.Id)
            .Select(x => new UserExceptionDto
            {
                Id = x.Id,
                UserLogin = x.UserLogin,
                SourceSystem = x.SourceSystem,
                ExceptionType = x.ExceptionType,
                Description = x.Description,
                IsActive = x.IsActive,
                CreatedAtUtc = x.CreatedAtUtc,
                ExpiresAtUtc = x.ExpiresAtUtc,
                CreatedBy = x.CreatedBy
            })
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<UserExceptionDto>> GetPageAsync(int skip, int take, CancellationToken cancellationToken = default)
    {
        return await _dbContext.UserExceptions
            .OrderByDescending(x => x.CreatedAtUtc)
            .ThenByDescending(x => x.Id)
            .Skip(skip)
            .Take(take)
            .Select(x => new UserExceptionDto
            {
                Id = x.Id,
                UserLogin = x.UserLogin,
                SourceSystem = x.SourceSystem,
                ExceptionType = x.ExceptionType,
                Description = x.Description,
                IsActive = x.IsActive,
                CreatedAtUtc = x.CreatedAtUtc,
                ExpiresAtUtc = x.ExpiresAtUtc,
                CreatedBy = x.CreatedBy
            })
            .ToListAsync(cancellationToken);
    }

    public Task<int> CountAsync(CancellationToken cancellationToken = default)
    {
        return _dbContext.UserExceptions.CountAsync(cancellationToken);
    }

    public async Task<UserExceptionDto?> GetByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        return await _dbContext.UserExceptions
            .Where(x => x.Id == id)
            .Select(x => new UserExceptionDto
            {
                Id = x.Id,
                UserLogin = x.UserLogin,
                SourceSystem = x.SourceSystem,
                ExceptionType = x.ExceptionType,
                Description = x.Description,
                IsActive = x.IsActive,
                CreatedAtUtc = x.CreatedAtUtc,
                ExpiresAtUtc = x.ExpiresAtUtc,
                CreatedBy = x.CreatedBy
            })
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<UserExceptionDto> CreateAsync(UserExceptionCreateRequest request, CancellationToken cancellationToken = default)
    {
        var entity = new UserException
        {
            UserLogin = request.UserLogin,
            SourceSystem = request.SourceSystem,
            ExceptionType = request.ExceptionType,
            Description = request.Description,
            IsActive = request.IsActive,
            ExpiresAtUtc = request.ExpiresAtUtc,
            CreatedBy = request.CreatedBy
        };

        _dbContext.UserExceptions.Add(entity);
        await _dbContext.SaveChangesAsync(cancellationToken);

        await _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = SecurityEventType.UserExceptionCreated,
            Severity = EventSeverity.Info,
            UserName = request.CreatedBy,
            Description = $"Создана запись UserException для пользователя {entity.UserLogin}.",
            AdditionalData = new { entity.Id, entity.SourceSystem, entity.ExceptionType }
        });

        return ToDto(entity);
    }

    public async Task<UserExceptionDto?> UpdateAsync(UserExceptionUpdateRequest request, CancellationToken cancellationToken = default)
    {
        var entity = await _dbContext.UserExceptions.FirstOrDefaultAsync(x => x.Id == request.Id, cancellationToken);
        if (entity is null)
        {
            return null;
        }

        entity.UserLogin = request.UserLogin;
        entity.SourceSystem = request.SourceSystem;
        entity.ExceptionType = request.ExceptionType;
        entity.Description = request.Description;
        entity.IsActive = request.IsActive;
        entity.ExpiresAtUtc = request.ExpiresAtUtc;

        await _dbContext.SaveChangesAsync(cancellationToken);

        await _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = SecurityEventType.UserExceptionUpdated,
            Severity = EventSeverity.Info,
            UserName = request.ChangedBy,
            Description = $"Изменена запись UserException #{entity.Id}.",
            AdditionalData = new { entity.Id, entity.UserLogin, entity.SourceSystem }
        });

        return ToDto(entity);
    }

    public async Task<bool> DeleteAsync(int id, string? userName, CancellationToken cancellationToken = default)
    {
        var entity = await _dbContext.UserExceptions.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (entity is null)
        {
            return false;
        }

        _dbContext.UserExceptions.Remove(entity);
        await _dbContext.SaveChangesAsync(cancellationToken);

        await _eventWriter.WriteAsync(new SecurityEventWriteRequest
        {
            EventType = SecurityEventType.UserExceptionDeleted,
            Severity = EventSeverity.Warning,
            UserName = userName,
            Description = $"Удалена запись UserException #{entity.Id}.",
            AdditionalData = new { entity.Id, entity.UserLogin, entity.SourceSystem }
        });

        return true;
    }


    private static UserExceptionDto ToDto(UserException x) => new()
    {
        Id = x.Id,
        UserLogin = x.UserLogin,
        SourceSystem = x.SourceSystem,
        ExceptionType = x.ExceptionType,
        Description = x.Description,
        IsActive = x.IsActive,
        CreatedAtUtc = x.CreatedAtUtc,
        ExpiresAtUtc = x.ExpiresAtUtc,
        CreatedBy = x.CreatedBy
    };
}
