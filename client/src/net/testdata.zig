//! Test vectors: certificates made by Portal itself (`portal run --listen
//! 127.0.0.1:8431` and `portal ca init` in two scratch data directories).
//! Public certificates only; the keys were thrown away.

/// Portal Local CA (5482a87f).
pub const ca_der = @embedFile("testdata/ca.der");
/// Its server certificate for 127.0.0.1 (valid 397 days from issue).
pub const leaf_der = @embedFile("testdata/leaf.der");
/// An unrelated Portal CA (0e6181ea), same name constraints.
pub const other_ca_der = @embedFile("testdata/other_ca.der");

pub const leaf_ip = "127.0.0.1";
/// A time inside both validity periods (2026-11-12).
pub const now_sec: i64 = 1794453818;
pub const ca_fingerprint = "9D:A8:05:77:8E:2F:9E:5B:20:36:2F:05:ED:2A:2C:6E:9F:4A:01:52:B8:8C:9E:6F:3A:F2:BF:1A:A6:9C:EE:0C";
