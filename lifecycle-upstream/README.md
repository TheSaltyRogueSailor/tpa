# Lifecycle store, upstream form

`server/tpa/store.ts` here is the DingDong-form source of `src/store.ts`.
`src/store.ts` is GENERATED from it; never edit `src/store.ts` directly:

```sh
node scripts/sync-lifecycle-store.mjs "$PWD/lifecycle-upstream/server/tpa/store.ts"
```

Why it lives here: the store used for the reviewed checkpoint (tag
`tpa-source-reviewed-2026-10-23`) is not present in any reachable upstream
branch. `dingdong@backup/tpa-validated-2026-10-23:server/tpa/store.ts` is an
older revision; regenerating from it would silently drop about 108 lines of
reviewed hardening. This file was reconstructed by inverting the sync
transform, and the sync script reproduces the reviewed `src/store.ts`
byte-for-byte from it (verified at reconstruction). Port any change made here
back to the DingDong source if that copy is still maintained.

This directory is not compiled or type-checked (its imports refer to DingDong paths).
