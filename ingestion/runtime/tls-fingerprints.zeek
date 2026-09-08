# Load only JA3, JA3S, and the BSD-licensed JA4 TLS-client implementation.
@load ja3/ja3.zeek
@load ja3/ja3s.zeek

module FINGERPRINT;

export {
    type Info: record {};
}

redef record connection += {
    fp: FINGERPRINT::Info &optional;
};

@load ja4/ja4
