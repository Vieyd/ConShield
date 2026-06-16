using ConShield.Data.Entities;

namespace ConShield.Data;

public static class DbSeeder
{
    public static async Task SeedAsync(ApplicationDbContext dbContext)
    {
        if (!dbContext.UserExceptions.Any())
        {
            dbContext.UserExceptions.AddRange(
                new UserException
                {
                    UserLogin = "svc-build",
                    SourceSystem = "CI/CD",
                    ExceptionType = "Временное исключение",
                    Description = "Временное исключение для тестового задания на этапе лабораторной работы.",
                    IsActive = true,
                    CreatedBy = "system",
                    ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
                },
                new UserException
                {
                    UserLogin = "runtime-user",
                    SourceSystem = "Runtime",
                    ExceptionType = "Исключение доступа",
                    Description = "Пример активной записи для проверки управления пользовательскими исключениями.",
                    IsActive = true,
                    CreatedBy = "system",
                    ExpiresAtUtc = DateTime.UtcNow.AddDays(14)
                });
        }

        if (!dbContext.SecurityEvents.Any())
        {
            dbContext.SecurityEvents.Add(new SecurityEventEntry
            {
                Description = "Инициализация журнала событий безопасности.",
                UserName = "system"
            });
        }

        await dbContext.SaveChangesAsync();
    }
}
