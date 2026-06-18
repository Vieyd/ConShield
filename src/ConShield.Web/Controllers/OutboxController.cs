using ConShield.Contracts.Constants;
using ConShield.EventPipeline;
using ConShield.MongoProjection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ConShield.Web.Controllers;

[Authorize(Roles = AppRoles.AdminIB)]
public class OutboxController : Controller
{
    private readonly SecurityEventOutboxStatusService _statusService;
    private readonly MongoProjectionStatusService _mongoStatusService;
    private readonly DeadLetterStatusService _deadLetterStatusService;

    public OutboxController(
        SecurityEventOutboxStatusService statusService,
        MongoProjectionStatusService mongoStatusService,
        DeadLetterStatusService deadLetterStatusService)
    {
        _statusService = statusService;
        _mongoStatusService = mongoStatusService;
        _deadLetterStatusService = deadLetterStatusService;
    }

    [HttpGet]
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var snapshot = await _statusService.GetSnapshotAsync(cancellationToken);
        ViewBag.MongoProjection = await _mongoStatusService.GetSnapshotAsync(cancellationToken);
        ViewBag.DeadLetters = await _deadLetterStatusService.GetSnapshotAsync(cancellationToken);
        return View(snapshot);
    }
}
