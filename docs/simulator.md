# Deterministic simulator

The `sim/` directory holds a deterministic simulator. It runs a whole miracache cluster in one process, on an
in-memory fabric (`SimFabric`) with a simulated clock and no sockets, and injects faults chosen by a seed: dropped,
delayed and reordered messages, killed and restarted memory nodes, crashes of the store, corrupted blocks, membership
changes and configuration reloads. After every step it checks the invariants of the protocol (no wrong bytes are ever
returned, writes commit at most once, leases and caps hold, a fetch is a hit or a clean miss, and so on).

A seed fully determines a run, so every failure is replayable. The sweep prints the failing seed; reproduce it alone:

```sh
build/sim/sim/sim_runner --seed 1234            # read scenario, prints the trace hash
build/sim/sim/sim_runner --store-seed 1234      # store scenario, run twice, must hash the same
build/sim/sim/sim_reload --seed 1234            # hot reload under load (replays the seed's plan)
```

The pinned trace hashes in `tests/sim/golden_*.txt` catch accidental behaviour changes: if a change is intentional,
re-record the hash with the command the failure message prints.

## Running a sweep

```sh
cmake --preset sim                       # 2000 seeds per sweep, store teeth hooks on
cmake --build --preset sim
ctest --preset sim -j 4                  # sim_smoke, sim_aead, sim_store_*of6, sim_store_vacuity, sim_reload_*
```

Each sweep is split into shards over disjoint seed ranges (`sim_store_1of6` ...; `-DMIRACACHE_SIM_SHARDS=N` changes
the count) so that `ctest -j` runs them side by side. For a quick run, lower the seed counts at configure time, for
example `-DMIRACACHE_SIM_SEEDS=60 -DMIRACACHE_STORE_SEEDS=60 -DMIRACACHE_AEAD_SEEDS=200 -DMIRACACHE_RELOAD_SEEDS=12`.
The "teeth" tests (`sim_store_teeth_*`) inject known store bugs and require the simulator to catch each one.
