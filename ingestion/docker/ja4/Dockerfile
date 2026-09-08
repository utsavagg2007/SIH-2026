ARG SOURCE_DATE_EPOCH=1786726820

FROM zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3 AS ja4-source
ARG SOURCE_DATE_EPOCH

COPY vendor/ja4-zeek/ /staged/usr/share/ja4-zeek/
COPY vendor/ja4-zeek/zeek/ /staged/usr/local/zeek/share/zeek/site/ja4/
COPY runtime/ja4-only.zeek /staged/usr/local/zeek/share/zeek/site/ja4-only.zeek

RUN find /staged -type d -exec chmod 0755 {} + \
    && find /staged -type f -exec chmod 0644 {} + \
    && find /staged -exec touch -h --date="@${SOURCE_DATE_EPOCH}" {} +

FROM zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3

LABEL org.opencontainers.image.title="SIH Zeek JA4-qualified runtime" \
      org.opencontainers.image.source="https://github.com/FoxIO-LLC/ja4-zeek-scripts" \
      io.sih.zeek.base-digest="sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3" \
      io.sih.ja4.upstream-commit="d03721fc1cd7e4519b3d86c677bd44f60aa81e53" \
      io.sih.ja4.upstream-tree="713e68527353c83e77b75c5b5715c85996ee1998" \
      io.sih.ja4.upstream-archive-sha256="800e0fc29f1af08ccedd45f22a4011cee40d3da54f45e5e4b5806a381bb08848" \
      io.sih.ja4.source-manifest-sha256="2d850af471d67e96253dbf93d18f0b8fbe1f40337551f65d7870a1995f8446e6" \
      io.sih.ja4.loader-sha256="75d57d8bdfcca2c464dece8b4c351966b0b38113a1a0f451ed409e77cc2a8daa"

COPY --from=ja4-source /staged/ /
