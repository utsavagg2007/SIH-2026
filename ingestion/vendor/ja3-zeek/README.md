# Vendored Salesforce JA3/JA3S Zeek source

This directory contains the minimum reviewed upstream source required to add
the TLS-client `ja3` and TLS-server `ja3s` fields to Zeek `ssl.log`.
Production execution performs no network fetch or package installation.

Upstream repository: `https://github.com/salesforce/ja3`
Upstream status: archived by its owner on 2025-05-01
Version declared by the two source files: JA3 1.4 and JA3S 1.1
Commit: `502cc6395811c54743b0561419d61900a6df3ff7`
Git tree: `d8853b0342166e6d1164869d318167de1931eb96`
Deterministic minimal git-archive SHA-256 (license and two Zeek scripts):
`e20442f7aa4916a28a6c9722f426aecd0ebc31a7c64b7fba6faaca56407cd9be`

`SOURCE-MANIFEST.sha256` authenticates every upstream file copied here, using
paths relative to this directory. The exact upstream BSD 3-Clause license is
preserved as `LICENSE.txt`, permitting source and binary redistribution when
its notice and terms are retained.

The source is intentionally minimal: `intel_ja3.zeek`, example lists, Python
implementations, and the package loader are not vendored or loaded. The two
scripts were executed successfully with the exact pinned Zeek 8.0.10 base
before selection. They add only `ja3` and `ja3s` to `ssl.log`; their auxiliary
debug logs are disabled by Zeek's normal `Log::disable_default_logs()` policy
used by this repository's runtime.
