# Load only the BSD-licensed JA4 TLS-client fingerprint implementation.
# The vendored package's other JA4+ algorithm modules are intentionally absent.
module FINGERPRINT;

export {
    type Info: record {};
}

redef record connection += {
    fp: FINGERPRINT::Info &optional;
};

@load ja4/ja4
