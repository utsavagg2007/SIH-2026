# Vendored FoxIO JA4 Zeek source

This directory contains the minimum reviewed upstream source needed to add the
TLS-client `ja4` field to Zeek `ssl.log`. Production execution does not fetch
source from the network.

Upstream repository: `https://github.com/FoxIO-LLC/ja4-zeek-scripts`
Published tag: `v1.0.0`
Commit: `d03721fc1cd7e4519b3d86c677bd44f60aa81e53`
Git tree: `713e68527353c83e77b75c5b5715c85996ee1998`
Deterministic full upstream git-archive SHA-256:
`800e0fc29f1af08ccedd45f22a4011cee40d3da54f45e5e4b5806a381bb08848`

`SOURCE-MANIFEST.sha256` authenticates every vendored file, using paths
relative to this directory. `UPSTREAM-zkg.meta` is the exact upstream
`zkg.meta`; `LICENSE-JA4PLUS` is the exact upstream root `LICENSE` renamed to
make its scope explicit.

JA4 TLS client fingerprinting is redistributed under the BSD 3-Clause terms
in `LICENSE-JA4`. The upstream root license for the separate JA4+ algorithms
is preserved in `LICENSE-JA4PLUS` for completeness. No JA4S, JA4H, JA4L,
JA4T, JA4TS, JA4SSH, JA4X, or JA4D algorithm module is vendored or loaded.
The shared configuration file contains their upstream option declarations but
does not load or implement those algorithms.

The runtime copies `zeek/` without alteration and loads it only through the
repository-controlled JA4-only loader.
