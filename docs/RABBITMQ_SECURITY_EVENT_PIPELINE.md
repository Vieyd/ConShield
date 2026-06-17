# RabbitMQ Security Event Pipeline

## Purpose

ConShield can deliver security event outbox messages through RabbitMQ instead of the local JSONL sink:

```text
SecurityEventWriter
-> PostgreSQL SecurityEvents + SecurityEventOutbox
-> RabbitMQ publisher confirm + mandatory routing
-> durable quorum queue
-> ConShield.EventConsumer
-> PostgreSQL SecurityEventInboxReceipts
-> manual ack
```

JSONL remains the default local transport. RabbitMQ is enabled only when `SecurityEventOutbox:Transport` is set to `RabbitMq`.

## Transport Mode

`SecurityEventOutbox:Transport` supports `Jsonl` and `RabbitMq`. There is no `Both` mode. A single dispatch attempt uses exactly one sink so a retry cannot duplicate JSONL after RabbitMQ fails.

## Topology

| Entity | Name | Type | Durable | Purpose |
| --- | --- | --- | --- | --- |
| Virtual host | `/conshield` | vhost | yes | isolates ConShield messages |
| Exchange | `conshield.security.events.v1` | topic | yes | security event publish target |
| Routing key | `security.event.created` | topic key | n/a | event-created route |
| Main queue | `conshield.security-events.consumer.v1` | quorum | yes | consumer queue |
| DLX | `conshield.security.events.dlx.v1` | topic | yes | dead-letter exchange |
| DL routing key | `security.event.dead` | topic key | n/a | dead-letter route |
| DLQ | `conshield.security-events.dead.v1` | queue | yes | poison/permanent messages |

The main queue declares `x-queue-type=quorum`, `x-dead-letter-exchange`, `x-dead-letter-routing-key`, and `x-delivery-limit=5`.

## Publisher Guarantees

`RabbitMqSecurityEventOutboxSink` uses RabbitMQ.Client 7.x async APIs, creates a confirm-enabled channel, publishes with `mandatory=true`, and marks the PostgreSQL outbox row `Delivered` only after the broker confirms the persistent message and routing is not returned as unroutable.

Transient failures include broker outage, connection recovery, publish timeout, nack, and mandatory return. Permanent failures include invalid envelope schema, oversized body, serialization failure, or invalid topology/configuration.

`Delivered` means broker-confirmed and routed. It does not mean the consumer has processed the message.

## Consumer Guarantees

`ConShield.EventConsumer` runs outside MVC/Web. It declares topology, uses `BasicQos`, consumes with `AsyncEventingBasicConsumer`, `autoAck=false`, copies the body inside the handler, validates message properties and JSON, and writes one inbox receipt in PostgreSQL before `BasicAckAsync(multiple:false)`.

`MessageId` is the inbox idempotency key. A crash after DB commit but before ack causes redelivery; the unique `MessageId` detects the duplicate, records no second side effect, and then acks. This is effectively-once for the PostgreSQL inbox side effect, not distributed exactly-once.

Permanent invalid messages are `BasicNackAsync(requeue:false)` and reach the DLQ. Transient processing failures are `BasicNackAsync(requeue:true)` and are bounded by the quorum delivery limit.

## Configuration

Tracked settings contain no secrets. Set credentials through environment variables:

```text
RabbitMq__UserName
RabbitMq__Password
```

TLS uses normal certificate validation; ConShield does not install an accept-any-certificate callback.

## Docker Compose

```powershell
$env:CONSHIELD_POSTGRES_PASSWORD = "<local-secret>"
$env:CONSHIELD_RABBITMQ_USER = "conshield"
$env:CONSHIELD_RABBITMQ_PASSWORD = "<local-secret>"
docker compose -f .\infra\docker-compose.yml --profile messaging up -d postgres rabbitmq
```

The management port is bound to `127.0.0.1` only. Do not commit broker data, credentials, or generated definitions.

## Status

Implemented:

- PostgreSQL outbox.
- JSONL transport.
- RabbitMQ transport.
- Idempotent PostgreSQL inbox consumer.
- DLQ.

Not implemented:

- MongoDB.
- Multi-destination fanout.
- Automatic DLQ replay.
- Distributed exactly-once.
- RabbitMQ cluster automation.
- Production TLS provisioning.
