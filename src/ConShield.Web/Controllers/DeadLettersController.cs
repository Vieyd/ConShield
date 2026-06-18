using ConShield.Contracts.Constants;
using ConShield.Data;
using ConShield.Data.Entities;
using ConShield.EventPipeline;
using ConShield.Web.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ConShield.Web.Controllers;

[Authorize(Roles = AppRoles.AdminIB)]
public class DeadLettersController : Controller
{
    private const int PageSize = 20;
    private readonly ApplicationDbContext _dbContext;
    private readonly DeadLetterReplayRequestService _replayRequestService;

    public DeadLettersController(ApplicationDbContext dbContext, DeadLetterReplayRequestService replayRequestService)
    {
        _dbContext = dbContext;
        _replayRequestService = replayRequestService;
    }

    [HttpGet]
    public async Task<IActionResult> Index(
        string? eligibility,
        string? reason,
        string? replayStatus,
        DateTime? capturedFromUtc,
        DateTime? capturedToUtc,
        int page = 1,
        CancellationToken cancellationToken = default)
    {
        page = Math.Max(1, page);
        var query = _dbContext.DeadLetterQuarantineMessages.AsNoTracking().Include(x => x.ReplayRequests).AsQueryable();
        if (Enum.TryParse<DeadLetterReplayEligibility>(eligibility, ignoreCase: true, out var parsedEligibility))
            query = query.Where(x => x.ReplayEligibility == parsedEligibility);
        if (!string.IsNullOrWhiteSpace(reason))
            query = query.Where(x => x.DeadLetterReason == reason);
        if (capturedFromUtc.HasValue)
            query = query.Where(x => x.CapturedAtUtc >= DateTime.SpecifyKind(capturedFromUtc.Value, DateTimeKind.Utc));
        if (capturedToUtc.HasValue)
            query = query.Where(x => x.CapturedAtUtc <= DateTime.SpecifyKind(capturedToUtc.Value, DateTimeKind.Utc));
        if (Enum.TryParse<DeadLetterReplayRequestStatus>(replayStatus, ignoreCase: true, out var parsedStatus))
            query = query.Where(x => x.ReplayRequests.Any(r => r.Status == parsedStatus));

        var total = await query.CountAsync(cancellationToken);
        var items = await query
            .OrderByDescending(x => x.CapturedAtUtc)
            .Skip((page - 1) * PageSize)
            .Take(PageSize)
            .Select(x => new DeadLetterListItemViewModel
            {
                QuarantineId = x.QuarantineId,
                OriginalMessageId = x.OriginalMessageId,
                PayloadSha256 = x.PayloadSha256,
                MessageType = x.MessageType,
                DeadLetterReason = x.DeadLetterReason,
                ReplayEligibility = x.ReplayEligibility,
                CapturedAtUtc = x.CapturedAtUtc,
                CaptureCount = x.CaptureCount,
                LatestReplayStatus = x.ReplayRequests.OrderByDescending(r => r.RequestedAtUtc).Select(r => r.Status.ToString()).FirstOrDefault()
            })
            .ToListAsync(cancellationToken);

        return View(new DeadLetterIndexViewModel
        {
            Items = items,
            Eligibility = eligibility,
            Reason = reason,
            ReplayStatus = replayStatus,
            CapturedFromUtc = capturedFromUtc,
            CapturedToUtc = capturedToUtc,
            Page = page,
            TotalPages = Math.Max(1, (int)Math.Ceiling(total / (double)PageSize))
        });
    }

    [HttpGet]
    public async Task<IActionResult> Details(Guid id, CancellationToken cancellationToken)
    {
        var message = await _dbContext.DeadLetterQuarantineMessages
            .AsNoTracking()
            .Include(x => x.ReplayRequests)
            .SingleOrDefaultAsync(x => x.QuarantineId == id, cancellationToken);
        if (message is null)
            return NotFound();

        return View(new DeadLetterDetailsViewModel
        {
            QuarantineId = message.QuarantineId,
            OriginalMessageId = message.OriginalMessageId,
            PayloadSha256 = message.PayloadSha256,
            MessageType = message.MessageType,
            SchemaVersion = message.SchemaVersion,
            SecurityEventId = message.SecurityEventId,
            OriginalExchange = message.OriginalExchange,
            OriginalRoutingKey = message.OriginalRoutingKey,
            DeadLetterExchange = message.DeadLetterExchange,
            DeadLetterQueue = message.DeadLetterQueue,
            ContentType = message.ContentType,
            CapturedAtUtc = message.CapturedAtUtc,
            FirstDeadLetteredAtUtc = message.FirstDeadLetteredAtUtc,
            LastDeadLetteredAtUtc = message.LastDeadLetteredAtUtc,
            DeadLetterReason = message.DeadLetterReason,
            ValidationCategory = message.ValidationCategory,
            ReplayEligibility = message.ReplayEligibility,
            PayloadLength = message.PayloadLength,
            HeaderSummaryJson = message.HeaderSummaryJson,
            CaptureCount = message.CaptureCount,
            EligibilityExplanation = message.EligibilityExplanation,
            ReplayHistory = message.ReplayRequests
                .OrderByDescending(x => x.RequestedAtUtc)
                .Select(x => new DeadLetterReplayHistoryViewModel
                {
                    ReplayRequestId = x.ReplayRequestId,
                    RequestedBy = x.RequestedBy,
                    RequestedAtUtc = x.RequestedAtUtc,
                    Reason = x.Reason,
                    Status = x.Status,
                    AttemptCount = x.AttemptCount,
                    PublishedAtUtc = x.PublishedAtUtc,
                    CompletedAtUtc = x.CompletedAtUtc,
                    LastErrorCode = x.LastErrorCode,
                    LastErrorSummary = x.LastErrorSummary,
                    ReplaySequence = x.ReplaySequence
                })
                .ToArray()
        });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Replay(Guid id, string reason, CancellationToken cancellationToken)
    {
        var user = User.Identity?.Name ?? "unknown";
        var result = await _replayRequestService.RequestAsync(id, user, reason, cancellationToken);
        TempData[result.Accepted ? "StatusMessage" : "ErrorMessage"] = result.Accepted
            ? "Replay request was queued."
            : "Replay request was rejected.";
        return RedirectToAction(nameof(Details), new { id });
    }
}
