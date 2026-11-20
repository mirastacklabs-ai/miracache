# miracache observability: Grafana dashboards and Prometheus alerts

Spec: the design spec, section 11. Grafana 10+, Prometheus 2.26+.

| File | What |
|---|---|
| `dashboards/miracache-cluster-overview.json` | Per memory node: hit rate, put commit latency, bytes, capacity, scopes, evictions, errors. Panels read `hostname (node_id)`. |
| `dashboards/miracache-client.json` | Per client host and memory node: fetch/store latency, failover reads, replica legs, `skipped_full`, tickets, reconnects, watchdog, quarantine, ID conflicts/mismatches. |
| `dashboards/miracache-fabric.json` | NIC/fabric rows: RDMA errors (memory node and client), connections, ticket rejects, in-flight jobs, landing pool, session state. |
| `alerts.yml` | 13 alert rules (memory node down or not scraped, hit rate collapse, fetch p99, replica `skipped_full`, watchdog, node ID conflict/mismatch, zombies, quarantined bytes, admin rejects, digest mismatch, client session down). |

## Import

Grafana: Dashboards > New > Import > upload the JSON; pick your Prometheus data source for the
`DS_PROMETHEUS` input. Variables: `node_id` and `hostname` (memory nodes), `client_host`
(the client's Prometheus `instance`).

Prometheus: add `rule_files: ["/etc/prometheus/miracache-alerts.yml"]` (copy `alerts.yml`), then
`promtool check rules alerts.yml`.

## Scrape config

Memory nodes serve `:9464/metrics`; every series carries `node_id`, and `miracache_node_info{node_id,hostname,addr}`
maps it to the host. Clients must expose their registry on a scrape port of their own (the embedding
process decides which); their series are keyed by `node="<first rail host:port>"`, and
`miracache_client_node_info{node,node_id,hostname,addr,zone}` maps that to the learned ID and hostname.

```yaml
scrape_configs:
  - job_name: miracache-memnode          # alerts.yml expects this job name
    static_configs:
      - targets: ["memnode-a:9464", "memnode-b:9464"]
  - job_name: miracache-client           # engine hosts; port is whatever the client process exposes
    static_configs:
      - targets: ["gpu-host-1:9464", "gpu-host-2:9464"]
```

Dashboards join on `instance`, so keep one target per process and do not relabel `instance` differently
between the two jobs for the same host.

## Notes

- The memory node measures no fetch latency (clients READ over RDMA without involving it). Fetch latency
  panels and the p99 alert therefore come from the client histogram `miracache_client_fetch_seconds`
  (`stage="total"`), per client host. Put latency is shown both ways (server `put_commit_seconds`, client `put_seconds`).
- The fetch p99 alert uses 5 ms (spec section 12, 16 MB on 1x100G); the 1 MB target is 900 us. Tune it to your block size.
- Per-rail memory-node metrics (`miracache_rail_state`, `miracache_qp_active`) are registered and shown in the "Memory node rails" row of the fabric dashboard. No CQ metric is registered yet. The fabric dashboard
  shows what exists; extend it when those land.
- Our CI fails when a dashboard or alert uses a `miracache_*` name the code does not register.
- OTLP tracing and the metering stream are deferred (spec section 15).
