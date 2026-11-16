# github-core-clone-01

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/lenhan54/makefun-github-core-clone/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/lenhan54/makefun-github-core-clone/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A single-process GitHub-compatible forge, written for
[github-core-clone-01](https://make.fun/bounty/github-core-clone-01): git smart
HTTP (upload-pack protocol v2, receive-pack v0), the REST v3 API, GraphQL v4,
and an MCP endpoint over streamable HTTP. One process, Node 22 standard
library only, everything held in memory.

## Run it

```sh
node --experimental-strip-types main.ts
```

The process binds an ephemeral port, registers it with the trial env at
`$MAKEFUN_ENV_URL`, serves until the env answers `{"done": true}`, then
exits 0. The bearer token it accepts is `$MAKEFUN_SHOP_TOKEN`.

## Layout

- `main.ts` — the entry/env lifecycle: bind, register, poll done, exit.
- `app.ts` — the whole forge: the object store and pack codec, the REST
  resources, the GraphQL executor, and the MCP tools.
- `LICENSE` (MIT), `.makefun/owner.json` — licence and claim file.

## Notes

- Objects are deflated once when stored; packs are assembled from the
  pre-deflated bytes, so clones never re-compress.
- No wall clock or randomness reaches an answer: timestamps come from
  `MAKEFUN_TRIAL_NOW` plus a monotone counter, ids from counters and SHA-1.
- Pushes are fast-forward only; a refused ref is reported per ref while the
  accepted refs in the same push still apply.
