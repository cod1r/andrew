const std = @import("std");
const env_vars = @import("env_vars.zig");
const libsodium = @cImport({
    @cInclude("sodium.h");
});
fn parse_http_message(buff: []u8, map: *std.StringArrayHashMap([]u8)) !usize {
    var newline_start_line: usize = undefined;
    {
        for (buff) |chr, idx| {
            if (chr == '\n') {
                newline_start_line = idx;
                break;
            }
        }
    }
    try map.put("start_line", buff[0..(newline_start_line + 1)]);
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
                // msg could not end with newline character
                newline_value_end = local_idx;
                break;
            }
        }
        // maybe strip header value?
        if (key_end > index and newline_value_end > key_end + 1) {
            var key = try alloc.alloc(u8, key_end - index);
            var value = try alloc.alloc(u8, newline_value_end - (key_end + 1));
            std.mem.copy(u8, key, buff[index..key_end]);
            std.mem.copy(u8, value, buff[key_end + 1..newline_value_end]);
            try map.put(key, buff[key_end + 1..newline_value_end]);
            index = newline_value_end;
        } else if (newline_value_end <= key_end + 1) {
            var key = try alloc.alloc(u8, key_end - index);
            var value = try alloc.alloc(u8, buff.len - (key_end + 1));
            std.mem.copy(u8, key, buff[index..key_end]);
            std.mem.copy(u8, value, buff[key_end + 1..buff.len]);
            try map.put(key, buff[key_end + 1..buff.len]);
            index = buff.len;
        } else if (key_end == index) {
            break;
        }
    }
    return index;
}

fn ACK(stream: std.net.Stream) !usize {
    return try stream.write(
        "HTTP/2.0 200 \t\r\nContent-Type: application/json\r\n\r\n'{\"type\": 1}'"
    );
}

var gpa = std.heap.GeneralPurposeAllocator(.{.safety = true}){};
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
        var map = try parse_http_message(buff[0..]);
        defer map.deinit();
        var signature = map.get("X-Signature-Ed25519") orelse "";
        var timestamp = map.get("X-Signature-Timestamp") orelse "";
        // verify request with libsodium
        //var verify = libsodium.crypto_sign_verify_detached(@ptrCast([*c]u8, signature.ptr), );
        if (verify == -1) {
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
    var map = std.StringArrayHashMap([]u8).init(std.testing.allocator);
    defer map.deinit();
    var msg_size = try parse_http_message(msg_copy, &map);
    try std.testing.expect(msg_size == msg.len);
    var content_type = map.get("Content-Type") orelse "";
    try std.testing.expect(std.mem.eql(u8, content_type, " application/json"));
    var start_line = map.get("start_line") orelse "";
    try std.testing.expect(std.mem.eql(u8, start_line, "POST / HTTP/1.1\r\n"));
}
