const std = @import("std");
const env_vars = @import("env_vars.zig");
const libsodium = @cImport({
    @cInclude("sodium.h");
});
fn parse_http_message(buff: []u8, map: *std.StringHashMap([]u8)) !usize {
    var newline_start_line: usize = 0;
    {
        for (buff) |chr, idx| {
            if (chr == '\n') {
                newline_start_line = idx;
                break;
            }
        }
    }
    if (newline_start_line > 0) {
        try map.put("start_line", buff[0..(newline_start_line + 1)]);
    } else {
        try map.put("start_line", buff[0..]);
    }
    var index: usize = newline_start_line + 1;
    while (index < buff.len) {
        if (index + 3 < buff.len and std.mem.eql(u8, buff[index..(index + 4)], "\r\n\r\n")) {
            break;
        }
        var key_end: usize = index;
        var newline_value_end: usize = index;
        var local_idx: usize = index;
        while (local_idx < buff.len) : (local_idx += 1) {
            if (buff[local_idx] == ':') {
                key_end = local_idx;
            } else if (buff[local_idx] == '\n') {
                // msg could not have newline character
                newline_value_end = local_idx;
                break;
            }
        }
        // maybe strip header value?
        if (key_end > index and newline_value_end > key_end + 1) {
            var key = try alloc.alloc(u8, key_end - index);
            var value = try alloc.alloc(u8, newline_value_end - (key_end + 1));
            std.mem.copy(u8, key, buff[index..key_end]);
            std.mem.copy(u8, value, buff[key_end + 1 .. newline_value_end]);
            try map.put(key, buff[key_end + 1 .. newline_value_end]);
            index = newline_value_end + 1;
        } else if (key_end > index and newline_value_end <= key_end + 1) {
            var key = try alloc.alloc(u8, key_end - index);
            var value = try alloc.alloc(u8, buff.len - (key_end + 1));
            std.mem.copy(u8, key, buff[index..key_end]);
            std.mem.copy(u8, value, buff[key_end + 1 .. buff.len]);
            try map.put(key, buff[key_end + 1 .. buff.len]);
            index = buff.len;
        } else {
            break;
        }
    }
    return index;
}

// Acknowledging the PING request from Discord
fn ACK(stream: std.net.Stream) !usize {
    return try stream.write("HTTP/1.1 200 \t\r\nContent-Type: application/json\r\n\r\n'{\"type\": 1}'");
}

// Bad Signature
fn BAD_SIG(stream: std.net.Stream) !usize {
    return try stream.write("HTTP/1.1 401 \t\r\n");
}

var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
var alloc = gpa.allocator();
pub fn main() !void {
    defer _ = gpa.deinit();
    const PORT = 8000;
    var add = try std.net.Address.parseIp("127.0.0.1", PORT);
    var ss = std.net.StreamServer.init(.{});
    defer ss.deinit();
    try ss.listen(add);
    std.debug.print("listening on port {}\n", .{PORT});
    while (true) {
        var conn = try ss.accept();
        var buff: [65536]u8 = undefined;
        var read_size = try conn.stream.read(buff[0..]);
        std.debug.print("{s}\n", .{buff[0..read_size]});
        var map = std.StringHashMap([]u8).init(alloc);
        defer map.deinit();
        var msg_size = try parse_http_message(buff[0..read_size], &map);
        var signature = map.get("X-Signature-Ed25519");
        var timestamp = map.get("X-Signature-Timestamp");
        if (signature != null and timestamp != null) {
            // adding 2 because of the CRLF empty line
            var timestamp_body = try std.mem.concat(
                alloc,
                u8,
                &[_][]u8{ timestamp.?, buff[msg_size + 2 ..] },
            );
            std.debug.print("crypto_sign_BYTES: {}\n", .{libsodium.crypto_sign_BYTES});
            std.debug.print("crypto_sign_PUBLICKEYBYTES: {}\n", .{libsodium.crypto_sign_PUBLICKEYBYTES});
            var timestamp_body_libsodium = try alloc.alloc(u8, libsodium.crypto_sign_BYTES);
            defer alloc.free(timestamp_body_libsodium);
            var public_key_libsodium = try alloc.alloc(u8, libsodium.crypto_sign_PUBLICKEYBYTES);
            defer alloc.free(public_key_libsodium);
            std.mem.copy(u8, timestamp_body_libsodium, timestamp_body);
            // verify request with libsodium
            var verify = libsodium.crypto_sign_verify_detached(
                @ptrCast([*c]const u8, timestamp_body_libsodium.ptr),
                @ptrCast([*c]const u8, signature.?),
                signature.?.len,
                @ptrCast([*c]const u8, public_key_libsodium.ptr),
            );
            if (verify == -1) {
                _ = try BAD_SIG(conn.stream);
            }
        }
        var sent_size = try ACK(conn.stream);
        std.debug.print("send: {} bytes\n", .{sent_size});
        conn.stream.close();
    }
}

test "parse http message" {
    var msg: []const u8 = "POST / HTTP/1.1\r\nContent-Type: application/json";
    var msg_copy = try std.testing.allocator.alloc(u8, msg.len);
    defer std.testing.allocator.free(msg_copy);
    std.mem.copy(u8, msg_copy, msg);
    var map = std.StringHashMap([]u8).init(std.testing.allocator);
    defer map.deinit();
    var msg_size = try parse_http_message(msg_copy, &map);
    try std.testing.expect(msg_size == msg.len);
    var content_type = map.get("Content-Type") orelse "";
    try std.testing.expect(std.mem.eql(u8, content_type, " application/json"));
    var start_line = map.get("start_line") orelse "";
    try std.testing.expect(std.mem.eql(u8, start_line, "POST / HTTP/1.1\r\n"));
}

test "env public key" {
    try std.testing.expect(env_vars.PUBLIC_KEY.len > 0);
}
