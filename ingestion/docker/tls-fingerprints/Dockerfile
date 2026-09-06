ARG SOURCE_DATE_EPOCH=1786726820

FROM zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3 AS fingerprint-source
ARG SOURCE_DATE_EPOCH

COPY vendor/ja3-zeek/ /staged/usr/share/ja3-zeek/
COPY vendor/ja3-zeek/zeek/ /staged/usr/local/zeek/share/zeek/site/ja3/
COPY vendor/ja4-zeek/ /staged/usr/share/ja4-zeek/
COPY vendor/ja4-zeek/zeek/ /staged/usr/local/zeek/share/zeek/site/ja4/
COPY runtime/tls-fingerprints.zeek /staged/usr/local/zeek/share/zeek/site/tls-fingerprints.zeek

RUN find /staged -type d -exec chmod 0755 {} + \
    && find /staged -type f -exec chmod 0644 {} + \
    && find /staged -exec touch -h --date="@${SOURCE_DATE_EPOCH}" {} +

FROM zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3

LABEL org.opencontainers.image.title="SIH Zeek JA3-JA3S-JA4 qualified runtime" \
      org.opencontainers.image.source="https://github.com/utsavagg2007/SIH-2026" \
      io.sih.zeek.base-digest="sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3" \
      io.sih.ja3.upstream-repository="https://github.com/salesforce/ja3" \
      io.sih.ja3.upstream-commit="502cc6395811c54743b0561419d61900a6df3ff7" \
      io.sih.ja3.upstream-tree="d8853b0342166e6d1164869d318167de1931eb96" \
      io.sih.ja3.upstream-archive-sha256="e20442f7aa4916a28a6c9722f426aecd0ebc31a7c64b7fba6faaca56407cd9be" \
      io.sih.ja3.source-manifest-sha256="36c9df1841981b41bf277e473a3afff87386d3b40cc096a535f9e19abeadd83f" \
      io.sih.ja4.upstream-commit="d03721fc1cd7e4519b3d86c677bd44f60aa81e53" \
      io.sih.ja4.upstream-tree="713e68527353c83e77b75c5b5715c85996ee1998" \
      io.sih.ja4.upstream-archive-sha256="800e0fc29f1af08ccedd45f22a4011cee40d3da54f45e5e4b5806a381bb08848" \
      io.sih.ja4.source-manifest-sha256="2d850af471d67e96253dbf93d18f0b8fbe1f40337551f65d7870a1995f8446e6" \
      io.sih.fingerprints.loader-sha256="986804562ccea9160309f273c3bb29a8081816e8467a77a133d6b078329903b4"

COPY --from=fingerprint-source /staged/ /
