# Decisions

This document records project decisions that should guide future development.

## 001. Keep the Application Layer as the Business Logic Boundary

Business rules, correlation logic, and application use cases should live in `ConShield.Application`. MVC controllers should orchestrate input/output only.

Reason: this keeps the UI replaceable and makes security rules easier to test.

## 002. Keep Persistent Entities in the Data Layer

EF Core entities and `ApplicationDbContext` stay in `ConShield.Data`.

Reason: persistence details should not leak into the web layer more than necessary.

## 003. Use `ISecurityEventWriter` for Security Events

Security-relevant operations should create events through `ISecurityEventWriter`.

Reason: a single event-writing boundary makes audit behavior easier to extend later with queues, external storage, or structured export.

## 004. Store Time in UTC

Database timestamps should be stored in UTC. The current UI displays GMT+3.

Reason: UTC storage avoids ambiguous timestamps and keeps future integrations predictable.

## 005. Treat RabbitMQ and MongoDB as Planned Infrastructure

`infra/docker-compose.yml` currently describes future infrastructure. RabbitMQ and MongoDB are not part of the running application flow yet.

Reason: public documentation must not overstate implemented capabilities.

## 006. Keep Demo Authentication Until Replaced Deliberately

The current authentication mechanism remains unchanged for now. Hardening should happen as a separate task.

Reason: replacing authentication touches user flows, authorization, tests, and documentation and should not be mixed with project context/test setup work.
