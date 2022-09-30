const std = @import("std");
const libsodium = @cImport({
    @cInclude("sodium.h");
});
const utils = @import("utils.zig");
const HTTP_Parse_Err = error{
    InvalidHttpMessage,
};
fn parse_http_message(buff: []u8, map: *std.StringHashMap([]u8)) !usize {
    var newline_start_line: usize = 0;
    for (buff) |chr, idx| {
        if (chr == '\n') {
            newline_start_line = idx;
            break;
        }
    }
    var first_space: usize = 0;
    for (buff) |chr, idx| {
        if (chr == ' ') {
            first_space = idx;
            break;
        }
    }
    if (first_space > 0) {
        try map.put("method", buff[0..first_space]);
    } else {
        return HTTP_Parse_Err.InvalidHttpMessage;
    }
    if (newline_start_line > 0) {
        try map.put("start_line", buff[0..(newline_start_line + 1)]);
    } else {
        try map.put("start_line", buff[0..]);
    }
    var index: usize = newline_start_line + 1;
    var read: usize = newline_start_line + 1;
    while (index < buff.len) {
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
        if (key_end > index and newline_value_end > key_end + 1) {
            var key = try alloc.alloc(u8, key_end - index);
            std.mem.copy(u8, key, buff[index..key_end]);

            var value_beginning: usize = key_end + 1;
            var value_end: usize = newline_value_end;
            if (buff[value_beginning] == ' ') value_beginning += 1;
            while (buff[value_end] == '\r' or buff[value_end] == ' ' or buff[value_end] == '\n') {
                value_end -= 1;
            }
            var value = try alloc.alloc(u8, value_end - value_beginning + 1);
            std.mem.copy(u8, value, buff[value_beginning .. value_end + 1]);

            try map.put(key, value);
            index = newline_value_end + 1;
            read += (newline_value_end + 1 - read);
        } else if (key_end > index and newline_value_end <= key_end + 1) {
            var key = try alloc.alloc(u8, key_end - index);
            std.mem.copy(u8, key, buff[index..key_end]);

            var value_beginning: usize = key_end + 1;
            if (buff[value_beginning] == ' ') value_beginning += 1;
            var value = try alloc.alloc(u8, buff.len - value_beginning);
            std.mem.copy(u8, value, buff[value_beginning..buff.len]);

            try map.put(key, value);
            index = buff.len;
            read += (buff.len - read);
        } else {
            break;
        }
    }
    return read;
}

// Acknowledging the PING request from Discord
fn ACK(stream: std.net.Stream) !void {
    return try stream.writer().writeAll(
        "HTTP/1.1 200 \r\nContent-Length: 11\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"type\": 1}",
    );
}

// Bad Signature
fn BAD_SIG(stream: std.net.Stream) !void {
    return try stream.writer().writeAll(
        "HTTP/1.1 401 \r\nContent-Length: 25\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ninvalid request signature",
    );
}

var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
var alloc = gpa.allocator();
pub fn main() !void {
    defer _ = gpa.deinit();
    const PORT_env = std.os.getenv("PORT").?;
    const ip_address = "0.0.0.0";
    var PORT: u16 = 0;
    for (PORT_env) |chr, idx| {
        PORT += (chr - '0') * (std.math.pow(u16, 10, @intCast(u16, PORT_env.len - 1 - idx)));
    }
    var add = try std.net.Address.parseIp(ip_address, PORT);
    var ss = std.net.StreamServer.init(.{});
    defer ss.deinit();
    try ss.listen(add);
    std.debug.print("listening on port {}\n", .{PORT});
    if (libsodium.sodium_init() < 0) {
        @panic("libsodium cannot be initialized\n");
    }
    std.debug.print("libsodium initialized\n", .{});
    while (true) {
        var conn = try ss.accept();
        var buff: [65536]u8 = undefined;
        var read_size = try conn.stream.reader().readAll(buff[0..]);
        std.debug.print("{}\n", .{read_size});
        if (read_size > 0) {
            var msg = buff[0..read_size];
            var map = std.StringHashMap([]u8).init(alloc);
            defer map.deinit();
            var msg_size = try parse_http_message(msg, &map);
            // adding 2 because of the CRLF empty line
            var body = msg[msg_size + 2 .. read_size];
            if (map.get("method")) |method| {
                if (std.mem.eql(u8, method, "GET")) {
                    try conn.stream.writer().writeAll("HTTP/1.1 200 \r\nContent-Length: 56\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<h1>This is cod1r's zig discord bot</h1>");
                } else if (std.mem.eql(u8, method, "POST")) {
                    if (std.mem.eql(u8, map.get("Content-Type").?, "application/json")) {
                        var parser = std.json.Parser.init(alloc, false);
                        defer parser.deinit();
                        var response_obj = try parser.parse(body);
                        var response_type = response_obj.root.Object.get("type").?.Integer;
                        switch (response_type) {
                            1 => {
                                // PING response type
                                var signature = map.get("X-Signature-Ed25519");
                                var timestamp = map.get("X-Signature-Timestamp");
                                var PUBLIC_KEY = std.os.getenv("andrew_bot_public_key");
                                if (signature != null and timestamp != null and PUBLIC_KEY != null) {
                                    if (!std.json.validate(body)) {
                                        @panic("NOT VALID JSON STRING");
                                    }
                                    var timestamp_body = try std.mem.concat(
                                        alloc,
                                        u8,
                                        &[_][]u8{ timestamp.?, body },
                                    );
                                    defer alloc.free(timestamp_body);

                                    var sig_hex = try utils.fromHex(alloc, signature.?);
                                    defer alloc.free(sig_hex);

                                    var public_key_hex = try utils.fromHex(alloc, PUBLIC_KEY.?);
                                    defer alloc.free(public_key_hex);

                                    // verify request with libsodium
                                    var verify = libsodium.crypto_sign_verify_detached(
                                        @ptrCast([*c]const u8, sig_hex.ptr),
                                        @ptrCast([*c]const u8, timestamp_body.ptr),
                                        @intCast(c_ulonglong, timestamp_body.len),
                                        @ptrCast([*c]const u8, public_key_hex.ptr),
                                    );
                                    if (verify == -1) {
                                        try BAD_SIG(conn.stream);
                                    } else {
                                        try ACK(conn.stream);
                                    }
                                } else {
                                    try conn.stream.writer().writeAll("HTTP/1.1 500 \r\nContent-Length: 0\r\nContent-Type: text/plain\r\n\r\n");
                                }
                            },
                            2 => {
                                // APPLICATION COMMAND response type
                                var interaction_data = response_obj.root.Object.get("data").?.Object;
                                var command_name = interaction_data.get("name").?.String;
                                if (std.mem.eql(u8, command_name, "test")) {
                                    try conn.stream.writer().writeAll("HTTP/1.1 200 \r\nContent-Length: 37\r\nContent-Type: application/json\r\n\r\n{\"type\":4,\"data\":{\"content\":\"hello\"}}");
                                } else if (std.mem.eql(u8, command_name, "greet")) {
                                    try conn.stream.writer().writeAll("HTTP/1.1 200 \r\nContent-Length: 78\r\nContent-Type: application/json\r\n\r\n{\"type\":4,\"data\":{\"content\":\"hello, it me andy-chan. i make zig go brr! UwU\"}}");
                                }
                            },
                            3 => {},
                            4 => {},
                            5 => {},
                            else => {},
                        }
                    }
                }
            }
        } else {
            try conn.stream.writer().writeAll("HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n");
        }
        conn.stream.close();
    }
}

test "parse http message" {
    var msg: []const u8 = "POST / HTTP/1.1\r\nContent-Type: application/json\r\n";
    var msg_copy = try std.testing.allocator.alloc(u8, msg.len);
    defer std.testing.allocator.free(msg_copy);
    std.mem.copy(u8, msg_copy, msg);
    var map = std.StringHashMap([]u8).init(std.testing.allocator);
    defer map.deinit();
    var msg_size = try parse_http_message(msg_copy, &map);
    try std.testing.expect(msg_size == msg.len);
    var content_type = map.get("Content-Type") orelse &[_]u8{};
    try std.testing.expect(std.mem.eql(u8, content_type, "application/json"));
    var start_line = map.get("start_line") orelse &[_]u8{};
    try std.testing.expect(std.mem.eql(u8, start_line, "POST / HTTP/1.1\r\n"));
}

test "env public key" {
    try std.testing.expect(std.os.getenv("andrew_bot_public_key").?.len > 0);
}

test "utils" {
    _ = utils;
}
