# Network policy files

One file per **public** network (cluster). Each is the single source of truth
for that network's per-network policy. It is both:

- **baked into the binary at build time** (CMake reads this directory and
  generates a compiled table; the binary never reads these files at runtime, so
  joining adds no extra point of failure - the same discipline as the seeds in
  `libs/core/include/tier/core/seeds.hpp`), and
- **parsed directly by external tooling** - e.g. an automation job that checks
  whether a freshly released version falls inside a public network's window, and
  the generator for the README table.

Private networks have no file here; they are driven by the `TIER_VERSION_RANGE`
override (and are unconstrained by default).

## Format

Plain `key = value` lines; `#` begins a comment on its own line (no trailing
inline comments). The file name is the network name (`[a-z0-9-]`, 1-32 chars).

Keys:

- `version_range` - the window of software versions allowed on the network, as
  `min,max` with **min inclusive and max exclusive** (the same grammar as the
  `TIER_VERSION_RANGE` environment override). `1.4.0,1.5.0` accepts every
  `1.4.x` and rejects `1.5.0`. Either side may be empty for an open bound
  (`1.4.0,` is `>= 1.4.0`); an empty value is unconstrained.

More per-network keys (preconfigured seeds, allowed roles) may move here later
to unify the per-network configuration; today only `version_range` lives here.

The build fails (via a unit test over the baked table) if a file's name is
invalid or its `version_range` does not parse, so a typo never ships.
