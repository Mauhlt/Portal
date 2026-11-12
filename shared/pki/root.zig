//! Portal's PKI code, shared by the server (its private CA, src/tls) and
//! the native client (certificate pinning, client/src/net):
//!
//!   der          bounds-checked DER reader and DER writer
//!   cert         X.509 reading for Portal's profile
//!   pem          one-certificate PEM writing and reading
//!   fingerprint  SHA-256 fingerprints, "AB:CD:..." text

pub const der = @import("der.zig");
pub const cert = @import("cert.zig");
pub const pem = @import("pem.zig");
pub const fingerprint = @import("fingerprint.zig");

test {
    _ = der;
    _ = cert;
    _ = pem;
    _ = fingerprint;
}
