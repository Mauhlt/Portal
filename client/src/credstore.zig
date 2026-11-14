//! Long-lived device credential storage in the OS credential store only:
//!
//!   Windows  Credential Manager (CredWriteW / CredReadW / CredDeleteW,
//!            CRED_TYPE_GENERIC, persisted for this user on this machine)
//!   macOS    Keychain generic password via Security.framework, loaded with
//!            dlopen (no SDK needed to build), this device only
//!            (kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
//!   iOS      the same Keychain code (Security.framework is dlopen'd from
//!            the dyld shared cache), with the item bound to this device
//!            and to Face ID: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
//!            (never in iCloud Keychain or a backup) plus a SecAccessControl
//!            with kSecAccessControlBiometryCurrentSet, so every read asks
//!            for Face ID and re-enrolling a face invalidates it. Reads use
//!            the app's last LAContext (`apple_auth_context`) when it has
//!            one, so unlocking the app and signing in take one Face ID.
//!            The tunnel extension's key (`saveUnattended`) has no Face
//!            ID ACL: this device only, readable while unlocked.
//!   both     saving deletes and re-adds, never updates in place, so an
//!            item planted beforehand never keeps its own access control
//!   Linux    a 0600 file per secret in a 0700 directory,
//!            $XDG_DATA_HOME/portal/secrets (default ~/.local/share/portal),
//!            refused on load unless both belong to this user and are
//!            private to it (no external dependency)
//!
//! The secret is never written anywhere else (no other file, argv or log).
//! Buffers that held it are zeroed by the caller (see tunnel/keys.zig).

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{ Unavailable, Failed, TooLong };

pub const max_secret = 256;
pub const max_target = 128;

const impl = switch (builtin.os.tag) {
    .windows => windows,
    .macos, .ios => apple,
    else => linux,
};

/// iOS: an evaluated LAContext (LocalAuthentication) to pass as
/// kSecUseAuthenticationContext, so a Keychain read right after the app's
/// own Face ID check does not ask again. Set by the iPhone section
/// (client/src/ios); unused elsewhere.
pub var apple_auth_context: std.atomic.Value(?*anyopaque) = .init(null);

/// Copies the stored secret into `out` and returns it, or null if none.
pub fn load(target: []const u8, out: []u8) Error!?[]u8 {
    return impl.load(target, out);
}

/// Creates or replaces the secret. On iOS it is bound to Face ID (see
/// the top of this file).
pub fn save(target: []const u8, secret: []const u8) Error!void {
    if (secret.len > max_secret) return error.TooLong;
    return if (impl == apple) apple.save(target, secret, apple.ios) else impl.save(target, secret);
}

/// Like `save`, but on iOS without Face ID: readable, with no prompt, by
/// Portal's own processes that share its Keychain group (the packet tunnel
/// extension) while the iPhone is unlocked, this device only. Elsewhere
/// the same as `save`.
pub fn saveUnattended(target: []const u8, secret: []const u8) Error!void {
    if (secret.len > max_secret) return error.TooLong;
    return if (impl == apple) apple.save(target, secret, false) else impl.save(target, secret);
}

/// Deletes the secret; succeeds if there was none.
pub fn delete(target: []const u8) Error!void {
    return impl.delete(target);
}

// ------------------------------------------------------------------ Windows

const windows = struct {
    const WINAPI: std.builtin.CallingConvention = .winapi;
    const FILETIME = extern struct { lo: u32, hi: u32 };
    const CREDENTIALW = extern struct {
        Flags: u32 = 0,
        Type: u32,
        TargetName: [*:0]u16,
        Comment: ?[*:0]u16 = null,
        LastWritten: FILETIME = .{ .lo = 0, .hi = 0 },
        CredentialBlobSize: u32,
        CredentialBlob: ?[*]u8,
        Persist: u32,
        AttributeCount: u32 = 0,
        Attributes: ?*anyopaque = null,
        TargetAlias: ?[*:0]u16 = null,
        UserName: ?[*:0]u16 = null,
    };
    const CRED_TYPE_GENERIC = 1;
    const CRED_PERSIST_LOCAL_MACHINE = 2;
    const ERROR_NOT_FOUND = 1168;

    extern "advapi32" fn CredWriteW(*const CREDENTIALW, u32) callconv(WINAPI) i32;
    extern "advapi32" fn CredReadW([*:0]const u16, u32, u32, *?*CREDENTIALW) callconv(WINAPI) i32;
    extern "advapi32" fn CredDeleteW([*:0]const u16, u32, u32) callconv(WINAPI) i32;
    extern "advapi32" fn CredFree(*anyopaque) callconv(WINAPI) void;
    extern "kernel32" fn GetLastError() callconv(WINAPI) u32;

    fn wide(s: []const u8, buf: *[max_target + 1:0]u16) Error![*:0]u16 {
        const n = std.unicode.utf8ToUtf16Le(buf[0..max_target], s) catch return error.Failed;
        buf[n] = 0;
        return buf[0..n :0].ptr;
    }

    fn load(target: []const u8, out: []u8) Error!?[]u8 {
        var tbuf: [max_target + 1:0]u16 = undefined;
        var cred: ?*CREDENTIALW = null;
        if (CredReadW(try wide(target, &tbuf), CRED_TYPE_GENERIC, 0, &cred) == 0) {
            if (GetLastError() == ERROR_NOT_FOUND) return null;
            return error.Failed;
        }
        const c = cred orelse return null;
        defer CredFree(c);
        const n = c.CredentialBlobSize;
        const blob = c.CredentialBlob orelse return null;
        defer std.crypto.secureZero(u8, blob[0..n]);
        if (n > out.len) return error.TooLong;
        @memcpy(out[0..n], blob[0..n]);
        return out[0..n];
    }

    fn save(target: []const u8, secret: []const u8) Error!void {
        var tbuf: [max_target + 1:0]u16 = undefined;
        var user = std.unicode.utf8ToUtf16LeStringLiteral("portal-client").*;
        var copy: [max_secret]u8 = undefined;
        defer std.crypto.secureZero(u8, &copy);
        @memcpy(copy[0..secret.len], secret);
        const cred: CREDENTIALW = .{
            .Type = CRED_TYPE_GENERIC,
            .TargetName = try wide(target, &tbuf),
            .CredentialBlobSize = @intCast(secret.len),
            .CredentialBlob = &copy,
            .Persist = CRED_PERSIST_LOCAL_MACHINE,
            .UserName = &user,
        };
        if (CredWriteW(&cred, 0) == 0) return error.Failed;
    }

    fn delete(target: []const u8) Error!void {
        var tbuf: [max_target + 1:0]u16 = undefined;
        if (CredDeleteW(try wide(target, &tbuf), CRED_TYPE_GENERIC, 0) == 0) {
            if (GetLastError() == ERROR_NOT_FOUND) return;
            return error.Failed;
        }
    }
};

// ------------------------------------------------------- macOS and iOS

const apple = struct {
    const ios = builtin.os.tag == .ios;
    /// kSecAccessControlBiometryCurrentSet.
    const biometry_current_set: usize = 1 << 3;
    const CFTypeRef = *anyopaque;
    const OSStatus = i32;
    const errSecItemNotFound: OSStatus = -25300;
    const kCFStringEncodingUTF8: u32 = 0x08000100;

    const Api = struct {
        CFStringCreateWithBytes: *const fn (?*anyopaque, [*]const u8, isize, u32, u8) callconv(.c) ?CFTypeRef,
        CFDataCreate: *const fn (?*anyopaque, [*]const u8, isize) callconv(.c) ?CFTypeRef,
        CFDataGetBytePtr: *const fn (CFTypeRef) callconv(.c) [*]const u8,
        CFDataGetLength: *const fn (CFTypeRef) callconv(.c) isize,
        CFDictionaryCreate: *const fn (?*anyopaque, [*]const CFTypeRef, [*]const CFTypeRef, isize, *const anyopaque, *const anyopaque) callconv(.c) ?CFTypeRef,
        CFRelease: *const fn (CFTypeRef) callconv(.c) void,
        SecItemCopyMatching: *const fn (CFTypeRef, *?CFTypeRef) callconv(.c) OSStatus,
        SecItemAdd: *const fn (CFTypeRef, ?*?CFTypeRef) callconv(.c) OSStatus,
        SecItemDelete: *const fn (CFTypeRef) callconv(.c) OSStatus,
        key_callbacks: *const anyopaque,
        value_callbacks: *const anyopaque,
        kSecClass: CFTypeRef,
        kSecClassGenericPassword: CFTypeRef,
        kSecAttrService: CFTypeRef,
        kSecAttrAccount: CFTypeRef,
        kSecValueData: CFTypeRef,
        kSecReturnData: CFTypeRef,
        kSecMatchLimit: CFTypeRef,
        kSecMatchLimitOne: CFTypeRef,
        kCFBooleanTrue: CFTypeRef,
        SecAccessControlCreateWithFlags: *const fn (?*anyopaque, CFTypeRef, usize, ?*?*anyopaque) callconv(.c) ?CFTypeRef,
        kSecAttrAccessControl: CFTypeRef,
        kSecAttrAccessible: CFTypeRef,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFTypeRef,
        kSecUseAuthenticationContext: CFTypeRef,
    };

    var api: ?Api = null;
    var libs: [2]?std.DynLib = .{ null, null };

    fn get() Error!*const Api {
        if (api) |*a| return a;
        var cf = std.DynLib.open("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation") catch return error.Unavailable;
        var sec = std.DynLib.open("/System/Library/Frameworks/Security.framework/Security") catch return error.Unavailable;
        libs = .{ cf, sec };
        var a: Api = undefined;
        inline for (@typeInfo(Api).@"struct".field_names, @typeInfo(Api).@"struct".field_types) |f_name, f_type| {
            const is_cf = comptime std.mem.startsWith(u8, f_name, "CF") or std.mem.startsWith(u8, f_name, "kCF") or
                std.mem.endsWith(u8, f_name, "callbacks");
            const lib = if (is_cf) &cf else &sec;
            if (comptime std.mem.startsWith(u8, f_name, "k")) {
                // Data symbols: the CFStringRef/CFBooleanRef variable.
                const p = lib.lookup(*const CFTypeRef, f_name) orelse return error.Unavailable;
                @field(a, f_name) = p.*;
            } else if (comptime std.mem.eql(u8, f_name, "key_callbacks")) {
                a.key_callbacks = lib.lookup(*const anyopaque, "kCFTypeDictionaryKeyCallBacks") orelse return error.Unavailable;
            } else if (comptime std.mem.eql(u8, f_name, "value_callbacks")) {
                a.value_callbacks = lib.lookup(*const anyopaque, "kCFTypeDictionaryValueCallBacks") orelse return error.Unavailable;
            } else {
                @field(a, f_name) = lib.lookup(f_type, f_name) orelse return error.Unavailable;
            }
        }
        api = a;
        return &api.?;
    }

    fn str(a: *const Api, s: []const u8) Error!CFTypeRef {
        return a.CFStringCreateWithBytes(null, s.ptr, @intCast(s.len), kCFStringEncodingUTF8, 0) orelse error.Failed;
    }

    fn query(a: *const Api, service: CFTypeRef, account: CFTypeRef, extra_k: []const CFTypeRef, extra_v: []const CFTypeRef) Error!CFTypeRef {
        var ks: [6]CFTypeRef = undefined;
        var vs: [6]CFTypeRef = undefined;
        ks[0] = a.kSecClass;
        vs[0] = a.kSecClassGenericPassword;
        ks[1] = a.kSecAttrService;
        vs[1] = service;
        ks[2] = a.kSecAttrAccount;
        vs[2] = account;
        for (extra_k, extra_v, 0..) |k, v, i| {
            ks[3 + i] = k;
            vs[3 + i] = v;
        }
        const n = 3 + extra_k.len;
        return a.CFDictionaryCreate(null, &ks, &vs, @intCast(n), a.key_callbacks, a.value_callbacks) orelse error.Failed;
    }

    fn load(target: []const u8, out: []u8) Error!?[]u8 {
        const a = try get();
        const service = try str(a, target);
        defer a.CFRelease(service);
        const account = try str(a, "portal-client");
        defer a.CFRelease(account);
        const ctx: ?CFTypeRef = if (ios) apple_auth_context.load(.acquire) else null;
        const q = if (ctx) |c|
            try query(a, service, account, &.{ a.kSecReturnData, a.kSecMatchLimit, a.kSecUseAuthenticationContext }, &.{ a.kCFBooleanTrue, a.kSecMatchLimitOne, c })
        else
            try query(a, service, account, &.{ a.kSecReturnData, a.kSecMatchLimit }, &.{ a.kCFBooleanTrue, a.kSecMatchLimitOne });
        defer a.CFRelease(q);
        var result: ?CFTypeRef = null;
        const st = a.SecItemCopyMatching(q, &result);
        if (st == errSecItemNotFound) return null;
        if (st != 0) return error.Failed;
        const data = result orelse return null;
        defer a.CFRelease(data);
        const len: usize = @intCast(@max(0, a.CFDataGetLength(data)));
        if (len > out.len) return error.TooLong;
        @memcpy(out[0..len], a.CFDataGetBytePtr(data)[0..len]);
        return out[0..len];
    }

    /// Every save deletes any existing item and adds a new one (never
    /// SecItemUpdate): an item planted beforehand under this name keeps
    /// its own access settings through an update, a fresh item gets ours.
    /// Deleting needs no authentication (an update of a Face ID item would
    /// ask for Face ID). Always this device only (never iCloud Keychain or
    /// a backup); with `biometry` (the iOS sign-in credential) also Face ID
    /// on every read, else readable while the device is unlocked.
    fn save(target: []const u8, secret: []const u8, biometry: bool) Error!void {
        const a = try get();
        const service = try str(a, target);
        defer a.CFRelease(service);
        const account = try str(a, "portal-client");
        defer a.CFRelease(account);
        const data = a.CFDataCreate(null, secret.ptr, @intCast(secret.len)) orelse return error.Failed;
        defer a.CFRelease(data);
        const old = try query(a, service, account, &.{}, &.{});
        defer a.CFRelease(old);
        const del = a.SecItemDelete(old);
        if (del != 0 and del != errSecItemNotFound) return error.Failed;
        const add = if (biometry) blk: {
            const acl = a.SecAccessControlCreateWithFlags(null, a.kSecAttrAccessibleWhenUnlockedThisDeviceOnly, biometry_current_set, null) orelse
                return error.Unavailable; // no Face ID / Touch ID enrolled
            defer a.CFRelease(acl);
            break :blk try query(a, service, account, &.{ a.kSecValueData, a.kSecAttrAccessControl }, &.{ data, acl });
        } else try query(a, service, account, &.{ a.kSecValueData, a.kSecAttrAccessible }, &.{ data, a.kSecAttrAccessibleWhenUnlockedThisDeviceOnly });
        defer a.CFRelease(add);
        if (a.SecItemAdd(add, null) != 0) return error.Failed;
    }

    fn delete(target: []const u8) Error!void {
        const a = try get();
        const service = try str(a, target);
        defer a.CFRelease(service);
        const account = try str(a, "portal-client");
        defer a.CFRelease(account);
        const q = try query(a, service, account, &.{}, &.{});
        defer a.CFRelease(q);
        const st = a.SecItemDelete(q);
        if (st != 0 and st != errSecItemNotFound) return error.Failed;
    }
};
// ------------------------------------------------------------------ Linux

/// A file per secret, no external dependency:
///   $XDG_DATA_HOME/portal/secrets/<file name> (default ~/.local/share/...)
/// The directories are created 0700 and the file 0600 (written to a
/// temporary file and renamed into place). Every access opens the
/// directory (no symlink followed) and works relative to that descriptor;
/// every load checks, on the opened directory and the opened file (statx
/// of the descriptors, not of the paths), that they belong to this user and
/// that neither group nor others can access them; anything else is refused
/// (error.Failed), never "fixed" silently. Buffers that held the secret are
/// wiped.
const linux = struct {
    const L = std.os.linux;

    fn ok(rc: usize) bool {
        return L.errno(rc) == .SUCCESS;
    }

    /// `<dir>/secrets` with every level created 0700 if missing, opened
    /// and checked. Caller closes it.
    fn openDir() Error!L.fd_t {
        var buf: [1024]u8 = undefined;
        var env_buf: [512]u8 = undefined;
        const base = blk: {
            if (envVar("XDG_DATA_HOME", &env_buf)) |x| if (x.len > 0 and x[0] == '/') break :blk std.fmt.bufPrint(&buf, "{s}/portal", .{x}) catch return error.TooLong;
            const home = envVar("HOME", &env_buf) orelse return error.Unavailable;
            break :blk std.fmt.bufPrint(&buf, "{s}/.local/share/portal", .{home}) catch return error.TooLong;
        };
        var tmp: [1024]u8 = undefined;
        // Each missing level, 0700 (existing parents such as ~/.local stay as they are).
        var i: usize = 1;
        while (i <= base.len) : (i += 1) {
            if (i < base.len and base[i] != '/') continue;
            const z = std.fmt.bufPrintSentinel(&tmp, "{s}", .{base[0..i]}, 0) catch return error.TooLong;
            _ = L.mkdir(z, 0o700);
        }
        const full = std.fmt.bufPrintSentinel(&tmp, "{s}/secrets", .{base}, 0) catch return error.TooLong;
        _ = L.mkdir(full, 0o700);
        const rc = L.open(full, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        if (!ok(rc)) return error.Failed;
        const fd: L.fd_t = @intCast(rc);
        errdefer _ = L.close(fd);
        try checkPrivate(fd, true);
        return fd;
    }

    fn envVar(comptime name: []const u8, buf: []u8) ?[]const u8 {
        const v = std.c.getenv(std.fmt.comptimePrint("{s}", .{name})) orelse return null;
        const s = std.mem.sliceTo(v, 0);
        if (s.len == 0 or s.len > buf.len) return null;
        @memcpy(buf[0..s.len], s);
        return buf[0..s.len];
    }

    /// The open file or directory `fd` is owned by this user, has no
    /// group/other permission bits and is of the right type.
    fn checkPrivate(fd: L.fd_t, want_dir: bool) Error!void {
        var st: L.Statx = undefined;
        if (!ok(L.statx(fd, "", L.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true }, &st))) return error.Failed;
        const fmt = st.mode & 0o170000;
        if (fmt != (if (want_dir) @as(u16, 0o040000) else 0o100000)) return error.Failed;
        if (st.uid != L.getuid() or st.mode & 0o077 != 0) return error.Failed;
    }

    /// Longest file name: every byte escaped, plus ".new".
    const max_name = 3 * max_target + 4;

    /// The file name for `target`, one-to-one (two targets never share a
    /// file): [A-Za-z0-9.-] stay, '/' becomes '_' (so the names in use,
    /// such as "Portal-tunnel_device-key", are what they always were), any
    /// other byte ('_' and '%' included) becomes "%xx" (hex), and so does
    /// a leading '.' (never a hidden file, "..", or a path separator).
    fn fileName(target: []const u8, suffix: []const u8, buf: *[max_name + 1]u8) Error![:0]const u8 {
        if (target.len == 0 or target.len > max_target) return error.TooLong;
        const hex = "0123456789abcdef";
        var n: usize = 0;
        for (target, 0..) |c, i| {
            const keep = switch (c) {
                'a'...'z', 'A'...'Z', '0'...'9', '-' => true,
                '.' => i != 0,
                else => false,
            };
            if (keep or c == '/') {
                buf[n] = if (c == '/') '_' else c;
                n += 1;
            } else {
                buf[n..][0..3].* = .{ '%', hex[c >> 4], hex[c & 15] };
                n += 3;
            }
        }
        @memcpy(buf[n..][0..suffix.len], suffix);
        n += suffix.len;
        buf[n] = 0;
        return buf[0..n :0];
    }

    fn load(target: []const u8, out: []u8) Error!?[]u8 {
        var nb: [max_name + 1]u8 = undefined;
        const name = try fileName(target, "", &nb);
        const d = try openDir();
        defer _ = L.close(d);
        const rc = L.openat(d, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (L.errno(rc)) {
            .SUCCESS => {},
            .NOENT => return null,
            else => return error.Failed,
        }
        const fd: L.fd_t = @intCast(rc);
        defer _ = L.close(fd);
        try checkPrivate(fd, false);
        var n: usize = 0;
        while (n < out.len) {
            const r = L.read(fd, out[n..].ptr, out.len - n);
            if (!ok(r)) {
                std.crypto.secureZero(u8, out[0..n]);
                return error.Failed;
            }
            if (r == 0) return out[0..n];
            n += r;
        }
        std.crypto.secureZero(u8, out);
        return error.TooLong;
    }

    fn save(target: []const u8, secret: []const u8) Error!void {
        var nb: [max_name + 1]u8 = undefined;
        var tb: [max_name + 1]u8 = undefined;
        const name = try fileName(target, "", &nb);
        const tmp = try fileName(target, ".new", &tb);
        const d = try openDir();
        defer _ = L.close(d);
        _ = L.unlinkat(d, tmp, 0);
        const rc = L.openat(d, tmp, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600);
        if (!ok(rc)) return error.Failed;
        const fd: L.fd_t = @intCast(rc);
        var good = ok(L.fchmod(fd, 0o600)); // whatever the umask did
        var n: usize = 0;
        while (good and n < secret.len) {
            const r = L.write(fd, secret[n..].ptr, secret.len - n);
            if (!ok(r) or r == 0) good = false else n += r;
        }
        good = good and ok(L.fsync(fd));
        _ = L.close(fd);
        if (!good or !ok(L.renameat(d, tmp, d, name))) {
            _ = L.unlinkat(d, tmp, 0);
            return error.Failed;
        }
    }

    fn delete(target: []const u8) Error!void {
        var nb: [max_name + 1]u8 = undefined;
        const name = try fileName(target, "", &nb);
        const d = try openDir();
        defer _ = L.close(d);
        switch (L.errno(L.unlinkat(d, name, 0))) {
            .SUCCESS, .NOENT => {},
            else => return error.Failed,
        }
    }
};

test "Linux secret file names are one-to-one and keep the names in use" {
    var a: [linux.max_name + 1]u8 = undefined;
    var b: [linux.max_name + 1]u8 = undefined;
    try std.testing.expectEqualStrings("Portal-tunnel_device-key", try linux.fileName("Portal-tunnel/device-key", "", &a));
    try std.testing.expectEqualStrings("Portal-tunnel_device-key-e2e1", try linux.fileName("Portal-tunnel/device-key-e2e1", "", &a));
    try std.testing.expectEqualStrings("Portal-tunnel_device-key.new", try linux.fileName("Portal-tunnel/device-key", ".new", &a));
    // Distinct targets the old mapping (everything else to '_') merged.
    const pairs = [_][2][]const u8{
        .{ "a/b", "a:b" }, .{ "a/b", "a_b" }, .{ "a_b", "a:b" }, .{ "a%5fb", "a_b" },
        .{ ".x", "/x" },   .{ ".x", "_x" },   .{ "a b", "a_b" }, .{ "%2ex", ".x" },
    };
    for (pairs) |p| try std.testing.expect(!std.mem.eql(u8, try linux.fileName(p[0], "", &a), try linux.fileName(p[1], "", &b)));
    try std.testing.expectEqualStrings("%2e.", try linux.fileName("..", "", &a));
    try std.testing.expectEqualStrings("a%3ab%5f%25", try linux.fileName("a:b_%", "", &a));
    const long: [max_target]u8 = @splat(':');
    try std.testing.expectEqual(@as(usize, linux.max_name), (try linux.fileName(&long, ".new", &a)).len);
    try std.testing.expectError(error.TooLong, linux.fileName("", "", &a));
}

test "credential store round trip" {
    if (builtin.os.tag != .windows and builtin.os.tag != .linux) return error.SkipZigTest; // the Keychain needs a signed app
    const target = "Portal-client-unittest/127.0.0.1:1";
    try delete(target);
    var buf: [max_secret]u8 = undefined;
    try std.testing.expect((try load(target, &buf)) == null);
    try save(target, "dev.first");
    try std.testing.expectEqualStrings("dev.first", (try load(target, &buf)).?);
    try save(target, "dev.second"); // replace
    try std.testing.expectEqualStrings("dev.second", (try load(target, &buf)).?);
    try saveUnattended(target, "dev.third");
    try std.testing.expectEqualStrings("dev.third", (try load(target, &buf)).?);
    try delete(target);
    try std.testing.expect((try load(target, &buf)) == null);
    try delete(target); // idempotent
}
