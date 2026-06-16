# Report Mapping

This document maps ConShield features to topics that can be described in a portfolio report, course paper, or GitHub project overview.

## Project Goal

ConShield demonstrates a small security monitoring workflow:

- collect security events;
- preserve audit context;
- detect suspicious event patterns;
- create SIEM-style alerts;
- escalate alerts into incidents;
- separate administrator and operator permissions.

## Feature Mapping

| Area | Current implementation | Evidence in repository |
| --- | --- | --- |
| Role-based access | `AdminIB` can perform critical actions, `Operator` is read-only for critical flows | Controllers in `src/ConShield.Web/Controllers` |
| Audit logging | Security events are written through `ISecurityEventWriter` | `src/ConShield.SecurityEvents` |
| Event storage | Security events are persisted through EF Core | `ApplicationDbContext.SecurityEvents` |
| User exception governance | Create, edit, delete, list, and details flows | `UserExceptionsController`, `UserExceptionService` |
| Incident handling | Incidents have severity, status, source event, and notes | `IncidentRecord`, `IncidentsController` |
| Database provider | PostgreSQL through Npgsql | `ConShield.Data`, `Program.cs`, EF Core migrations |
| SIEM correlation | Rules generate alerts and incidents from event windows | `SiemCorrelationService` |
| Detection catalog | Human-readable rule definitions | `SiemRuleCatalog` |
| Local demo | Scenario generation for repeatable walkthroughs | `SiemController.GenerateScenario` |

## Detection Rule Mapping

| Rule | Meaning | Current trigger |
| --- | --- | --- |
| `BF-001` | Possible brute-force attempt | 3 or more login failures for one user in 2 minutes |
| `UE-001` | Suspicious user exception activity | 5 or more user exception update/delete events by one user in 30 seconds |
| `CR-001` | Repeated critical events from one source | 2 or more critical events from one source IP in 5 minutes |

## Portfolio Strengths

- The project is domain-specific to information security.
- It includes both preventive access control and detective monitoring.
- It contains testable detection logic.
- It has a roadmap toward event-driven SIEM architecture.

## Future Report Sections

- Threat model.
- Detection engineering approach.
- Incident lifecycle.
- Audit event taxonomy.
- Role model and access boundaries.
- Planned RabbitMQ/MongoDB event pipeline. These components are not active in the current runtime flow.
