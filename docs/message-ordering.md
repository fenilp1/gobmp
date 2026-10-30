# BMP publication order

Each BMP connection has its own parser and producer. The producer processes
frames in input order and completes all `Publisher.PublishMessage` calls for one
frame before processing the next frame. An announcement followed by a withdrawal
therefore reaches the publisher in that order. Peer state changes and the existing
End-of-RIB outputs follow the same sequence.

This guarantee applies to publication calls within one connection. It does not
provide global ordering across connections or Kafka/NATS topics, broker delivery
acknowledgements, or a cross-topic commit barrier; flushing at shutdown is
described below.
It also does not change which UPDATEs are recognized as End-of-RIB.

## Traffic before Peer Up

[RFC 7854 section 3.3](https://www.rfc-editor.org/rfc/rfc7854.html#section-3.3)
places Peer Up before the initial Route Monitoring messages. Parsed Route
Monitoring and Statistics received before the connection's first valid Peer Up
are skipped with a diagnostic. They are not buffered or allowed to block a later
Peer Up. Once that initial Peer Up has been processed, existing peer-identity and
capability handling continues unchanged.

RAW mode does not require Peer Up. Each received frame is encapsulated in the
OpenBMP envelope and published in input order with its BMP bytes preserved.

## Concurrency and shutdown limits

Different connections retain independent producers. A slow backend call on one
connection does not serialize the producers of other connections, although the
shared backend may impose its own resource limits.

Processing within one connection is sequential. Slow publication applies
backpressure instead of creating a goroutine for every frame; throughput for a
single busy connection may consequently differ. No throughput improvement is
claimed.

On EOF, connection error or server stop, the connection worker closes the
router's connection, so a router or active-mode redial need not wait for a slow
publisher, then closes its parser input and waits for it to drain, then closes
producer input and waits for its publication calls to finish. A complete frame handed to the parser is accepted.
All resulting valid messages finish their local publication calls before the
worker returns; the server waits for every worker before calling publisher.Stop.
Malformed/unsupported frames and parsed traffic before the first valid Peer Up
retain the skip rules above. Incomplete trailing frames are never published.

The standalone parser/producer APIs still support an explicit stop signal. The
server uses input closure instead, so shutdown does not abort an accepted frame.
`PublishMessage` has no cancellation parameter: a blocked call must return before
that connection worker and server Stop can finish. After SIGINT or SIGTERM,
gobmp bounds shutdown at 25 s: if server Stop has not returned by then, it exits
with status 1 and messages not yet published are lost. The 25 s fit within the
default 30 s Kubernetes grace period; Docker's default stop timeout is 10 s, so
raise it to at least 30 s (`docker stop -t 30`, Compose `stop_grace_period`) or
the container is killed before the deadline. The Kafka publisher's Stop waits
until every buffered message is delivered or fails. The NATS publisher, which
reconnects for as long as the server is away, publishes to JetStream
asynchronously, in call order: a publish returns before its acknowledgement, so
an acknowledgement failure or timeout (`nats_ack_timeout_ms`, default 30 s) does
not reach the caller; it is logged, at most once a second, and the message is
lost. Once `nats_max_pending_acks` (default 4096) acknowledgements are
outstanding, as during a JetStream outage, a publish waits for one, stalling
reads from that BMP connection. The NATS publisher's Stop waits up to 10 s for
outstanding acknowledgements.

Regression tests exercise actual BMP wire frames through the parser/producer
pipeline, including announcement, withdrawal, explicit End-of-RIB and Peer Down,
plus RAW byte order, early traffic, queue closure, stop and independent producers.
Immediate EOF, truncated tails and server stop also verify that accepted parsed
and RAW publications finish before publisher shutdown, including a blocked final
publication. Parser closure leaves its output channel owned by the caller.
These checks do not substitute for real-router or live-broker load acceptance.
