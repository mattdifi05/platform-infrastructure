# Control Center UI Contract

Status: T20 candidate implemented and verified in sandbox. It is not deployed live.

## Scope

The Control Center frontend is a server-rendered operations shell enhanced by the local JavaScript and CSS assets under `control-center/styles`. T20 keeps the existing backend and state contracts from T19 while making navigation, Status progress and responsive behavior deterministic.

## Stable shell

- Initial HTML renders the usable shell directly; there is no blocking preload screen.
- Dynamic navigation preserves the `main`, sidebar and page container identities.
- The same navigation-pill node is moved between server-rendered sidebar snapshots, so animation continues from its actual previous position.
- Rapid clicks use latest-navigation-wins cancellation. An expected aborted request is not presented as an error.
- Sidebar expansion, focus and scroll position are restored without replacing the body.
- On compact viewports only the active navigation group is expanded automatically. The sidebar becomes a bounded sticky panel in normal document flow.

## Cache contract

- Client HTML cache: 32-entry LRU-style bound, 15-second TTL and ETag revalidation.
- Prefetch: hover/focus only, 1.2-second timeout and no recursive preload.
- Server HTML context cache: coalesced, 2-second TTL and keyed by project/state identity.
- Every non-GET request invalidates the server HTML cache before building fresh mutation context.
- Versioned `/control/*` APIs bypass the HTML context cache and remain fresh.
- CSS/JavaScript assets use a versioned URL, ETag and `must-revalidate` cache policy.

## Status execution

Status does not animate simulated work. The client creates a validated run ID, opens `/control/v1/status/events/stream`, and advances only from persisted ordered events emitted by the typed T19 executor. The final POST response reconciles the rendered result. Duplicate run IDs fail closed.

## Action semantics

- The desktop sidebar has four direct destinations: `Panoramica`, `Applicazioni`, `Secret` and `Impostazioni`. Individual applications are opened from the searchable, folder-grouped application list. The existing logout action is fixed at the top-right of the viewport.
- Application detail pages place visibility and private-copy controls beside databases. They do not expose individual application backup or restore controls.
- Visibility changes show the actual plan, authentication, application and verification phases. Provider calls without granular progress use an indeterminate bar; completion requires a successful readback.
- `Panoramica` is the first destination and displays host CPU, RAM, disk, inode, swap, network, I/O and pressure readings. `Impostazioni` retains configuration and the global server backup switch. Host metrics refresh every 2 seconds only while Overview is active and visible, using the existing Prometheus node-exporter sampler. They never fall back to the Control Center container. CPU, network and I/O rates average the last 2 minutes; missing or stale values remain unavailable.
- Overview graphs use a shared animation frame loop and a 3-second presentation buffer. The visible 2-minute window clips and interpolates only between adjacent measured points, preserving both boundaries when samples enter or leave. The numeric labels show the latest actual response; the visual buffer does not add measurements or requests. Hidden views suspend animation, reduced-motion preferences are respected, and missing readings remain gaps. Detailed interface/disk tables and the system/filesystem text blocks are omitted.
- The global backup switch waits for the native root worker's persisted readback. OFF suspends native scheduled/manual capture and FTP publication; it does not delete copies or disable provider-managed backups. Restore authority remains separate.
- Missing or stale metrics are rendered as unavailable; measured zero remains distinct from unavailable.

## Browser and accessibility evidence

The isolated candidate used synthetic tmpfs project, database and metrics data only. The verified flow was:

`Status -> rapid category navigation -> application detail -> file search -> mobile reload`.

Evidence covers desktop 1440x1000, a 700-pixel-high overflow exercise and mobile 390x844. It records page identity, meaningful content, focus, sidebar scroll, pill geometry, duplicate IDs, named controls, Chromium accessibility-tree names, horizontal overflow, console/page errors and failed requests. The bundled Browser plugin did not expose its required control command in this session, so the evidence records the fallback to the bundled Playwright runtime and an isolated Chrome process.

## Rollout gate

Do not deploy this candidate until T01/T02 admin authentication, fresh T07/T08 recovery evidence, a reviewed workload lock and a maintenance window are approved. Rollback selects the previous verified Control Center image. Never delete volumes and never use `docker compose down -v`.
