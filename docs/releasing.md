# Releasing

The relay deploys to Fly by hand (`fly deploy --ha=false`, see `fly.toml`). A
`v*` tag marks a release and tells the streamer about it. There is no
semantic-release here: the relay is not published to npm, and its
`package.json` version stays `0.0.0`.

## Cut a release

1. Merge the change to `main` through a PR and deploy it.
2. If the relay's key changed, follow *Rotating the key* below instead: the
   repository variable `RELAY_PUBLIC_KEY` must be updated before tagging (the
   key is logged at boot as `relayPublicKey`).
3. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.

`.github/workflows/notify-streamer.yml` then sends `relay-released` to
`RonenMars/threadbase-streamer` with the tag and the public key. The streamer's
`update-relay.yml` rewrites the key it pins in `src/relay/hosted.ts` and opens a
PR against its `main` branch; if the key is unchanged it opens nothing. Streamer
side and secrets: `docs/guides/releasing.md` in that repo.

## Setup

| Where | Name | What |
| ----- | ---- | ---- |
| this repo, secret | `STREAMER_DISPATCH_PAT` | PAT able to dispatch to the streamer repo |
| this repo, variable | `RELAY_PUBLIC_KEY` | public key of the deployed `RELAY_STATIC_KEY` |
| streamer repo, secret | `RELAY_VER_BUMP_PAT` | PAT so the bump PR runs CI |

## Rotating the key

A streamer pins the key it was built with and the relay serves one key at a
time, so there is no overlap: a streamer on the old key cannot reach a relay on
the new one, and the reverse. So the order is:

1. Set `RELAY_PUBLIC_KEY` to the new public key.
2. Tag and push, without deploying the new `RELAY_STATIC_KEY` yet.
3. Let the streamer's `update-relay.yml` PR merge and its release land.
4. Only then change `RELAY_STATIC_KEY` and `fly deploy --ha=false`.

Streamers that have not updated yet are cut off from step 4 until they do.
