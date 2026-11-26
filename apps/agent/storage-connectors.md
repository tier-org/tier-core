# Collector storage connectors

This design adds a storage choice to `tier-agent`. A collector selects one
backend at startup. The built-in file store is the default for existing
deployments. PostgreSQL is the first external connector and serves as the
reference implementation for adding another backend through a GitHub pull
request. The configuration and SQL schema below describe the planned behavior.

## Collector and connector responsibilities

The collector owns the Tier subscription, sender authorization, envelope
decoding, and bounded deduplication by message ID. Move deduplication out of
`Store` so it applies identically to every backend. Keep the existing Tier
telemetry format.

The collector passes each accepted batch to the selected sink with the
authenticated sender ID, Tier message ID, and decoded envelope. The message
ID lets a connector identify a replay when a write may have committed before
the connection dropped. The connector owns storage mapping, connection
management, and write retries. `write()`
may borrow data for the duration of the call. A connector that queues work
must own the queued data. `flush()` gives the connector an opportunity to
finish pending work at shutdown within a bounded time. [Current `Sink` interface](src/sink.hpp)

The local backend retains its directory layout, retention settings, and
optional `tier-agent query` socket. PostgreSQL exposes reads through SQL.
The collector rejects an explicitly configured `query_socket` in PostgreSQL
mode. Future connectors can expose reads through their backend's native
interface. Simultaneous writes to multiple backends are a separate feature.

## Backend selection

The proposed configuration uses `backend` under `[collector]`, with `local`
as the default. Existing local configurations continue to work as written.
Each external backend gets its own settings section. For PostgreSQL, the
`dsn_env` setting names the environment variable containing the connection
string. Keep the connection string and credentials out of diagnostic logs.

```toml
role = "collector"

[collector]
backend = "postgresql"

[collector.postgresql]
dsn_env = "TIER_AGENT_POSTGRES_DSN"
```

Unknown backends and incomplete PostgreSQL settings should produce startup
errors that name the invalid setting. The existing `store`, `retention`,
`max_bytes`, and `snapshot_interval` settings apply to the local backend.
PostgreSQL event retention is managed on the database side.

## PostgreSQL storage model

| Tier data | PostgreSQL representation |
| --- | --- |
| Gauge | One row per authenticated sender and key. Each update replaces the stored value and the sender timestamp, following the collector's receive order. |
| Event | One row per sample. Keep the sender, key, value, and sender timestamp. Use the sender, message ID, and sample index to make retrying a write safe while allowing identical events from different messages. |

Store keys and values as `bytea`. The Tier decoder reads both as
length-delimited bytes, so this preserves their exact contents, including
embedded zero bytes. Numbers and strings keep their original representation.
[PostgreSQL binary data types](https://www.postgresql.org/docs/current/datatype-binary.html)

Write each envelope in a transaction using parameterized statements. Update
gauge rows with an upsert and insert event rows with conflict handling on
their event identity. Keep the schema under version control and document how
operators install it and grant the collector the permissions it needs.
[PostgreSQL INSERT and conflict handling](https://www.postgresql.org/docs/current/sql-insert.html#SQL-ON-CONFLICT)

Run SQL writes on a background worker to keep the Tier subscription
responsive during database outages. Use the existing `Sink` policy of a
bounded queue with oldest-first eviction. Retry transient failures with
backoff and preserve the order of retained batches. Log queue overflow and
permanent write failures
with enough context to diagnose them. An in-memory queue loses uncommitted
batches on collector restart. PostgreSQL durability applies once the
transaction commits.

## Adding a connector

1. Implement `Sink` for the backend. Describe which Tier sample types it can
   represent, how it maps them, and how operators can read them back.
2. Add the backend to the collector's startup selection. Define and validate
   its settings, and add a copyable config example with secret handling.
3. Document connection requirements, retries and drop behavior, retention,
   and any data type restrictions. Report unsupported inputs in a way that
   operators can diagnose without flooding the logs.
4. Add an integration test against the real backend. Submit the connector,
   configuration example, and test together in the GitHub pull request.

For PostgreSQL, the integration test should send a numeric gauge, a string
gauge, and an event through Tier and check all three through SQL. Update a
gauge and verify there is one row with the final value. Check that distinct
events remain distinct and that a retry produces one event row per sample.
Also verify that existing local configurations still work with `tier-agent query`
and that the Linux amd64 build and package include the PostgreSQL connector's
dependencies.

A later Prometheus Remote Write connector can use the same interface and
export numeric gauges, with rate-limited warnings for skipped string values.
