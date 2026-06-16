# AGENTS.md

Rules for future changes in ConShield:

- `ConShield.Web` contains only the MVC interface, controllers, view models, and configuration.
- Business logic must live in `ConShield.Application`.
- Data access and persistent entities live in `ConShield.Data`.
- All security events are created through `ISecurityEventWriter`.
- Controllers must stay thin.
- Time is stored in UTC, and the interface displays GMT+3.
- `Operator` has read-only access to critical functions.
- Do not use the words "лабораторная работа", "учебный стенд", `Pack4`, `Pack5`, or similar internal labels in the interface.
- Do not treat RabbitMQ and MongoDB as implemented components until they are actually connected.
- After changes, run restore, build, and tests.
