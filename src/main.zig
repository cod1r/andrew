const std = @import("std");
const libsodium = @cImport({
    @cInclude("sodium.h");
});
pub const openssl = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/bio.h");
});
const utils = @import("utils.zig");

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
    var PORT: u16 = @intCast(u16, utils.parseInt(PORT_env));
    var add = try std.net.Address.parseIp(ip_address, PORT);
    var ss = std.net.StreamServer.init(.{});
    defer ss.deinit();
    try ss.listen(add);
    if (libsodium.sodium_init() < 0) {
        @panic("libsodium cannot be initialized\n");
    }
    while (true) {
        var conn = try ss.accept();
        var headers_buffer: [65536]u8 = undefined;
        var headers_read_size: usize = try utils.read_header(&headers_buffer, conn.stream);
        if (headers_read_size > 0) {
            var map = std.StringHashMap([]const u8).init(alloc);
            defer map.deinit();
            var msg = headers_buffer[0..headers_read_size];
            var msg_size = utils.parse_http_message(msg, &map);
            if (msg_size) |parsed_msg_size| {
                var content_length = map.get("content-length");
                if (content_length) |cl| {
                    var content_length_number: usize = utils.parseInt(cl);
                    var body_buffer = try alloc.alloc(u8, content_length_number);
                    defer alloc.free(body_buffer);
                    var body_initial = msg[parsed_msg_size..headers_read_size];
                    std.mem.copy(u8, body_buffer, body_initial);
                    var body_buffer_len = headers_read_size - parsed_msg_size;
                    if (headers_read_size - parsed_msg_size < content_length_number) {
                        var read_body = try conn.stream.reader().read(body_buffer[body_buffer_len..]);
                        while (read_body < content_length_number) {
                            read_body += try conn.stream.reader().read(body_buffer[body_buffer_len + read_body ..]);
                        }
                        body_buffer_len += read_body;
                    }
                    if (map.get("method")) |method| {
                        if (std.mem.eql(u8, method, "GET")) {
                            try conn.stream.writer().writeAll("HTTP/1.1 200 \r\nContent-Length: 40\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<h1>This is cod1r's zig discord bot</h1>");
                        } else if (std.mem.eql(u8, method, "POST")) {
                            if (std.mem.eql(u8, map.get("content-type").?, "application/json")) {
                                var parser = std.json.Parser.init(alloc, false);
                                defer parser.deinit();
                                if (std.json.validate(body_buffer)) {
                                    var response_obj = try parser.parse(body_buffer);
                                    var response_type = response_obj.root.Object.get("type").?.Integer;
                                    switch (response_type) {
                                        1 => {
                                            // PING response type
                                            var signature = map.get("x-signature-ed25519");
                                            var timestamp = map.get("x-signature-timestamp");
                                            var PUBLIC_KEY = std.os.getenv("andrew_bot_public_key");
                                            if (signature != null and timestamp != null and PUBLIC_KEY != null) {
                                                var timestamp_body = try std.mem.concat(
                                                    alloc,
                                                    u8,
                                                    &[_][]const u8{ timestamp.?, body_buffer },
                                                );
                                                defer alloc.free(timestamp_body);

                                                var sig_hex = utils.fromHex(alloc, signature.?);
                                                var public_key_hex = utils.fromHex(alloc, PUBLIC_KEY.?);
                                                if (sig_hex) |signature_hex| {
                                                    defer alloc.free(signature_hex);
                                                    if (public_key_hex) |pc_hex| {
                                                        defer alloc.free(pc_hex);
                                                        // verify request with libsodium
                                                        var verify = libsodium.crypto_sign_verify_detached(
                                                            @ptrCast([*c]const u8, signature_hex.ptr),
                                                            @ptrCast([*c]const u8, timestamp_body.ptr),
                                                            @intCast(c_ulonglong, timestamp_body.len),
                                                            @ptrCast([*c]const u8, pc_hex.ptr),
                                                        );
                                                        if (verify == -1) {
                                                            try BAD_SIG(conn.stream);
                                                        } else {
                                                            try ACK(conn.stream);
                                                        }
                                                    } else |err| std.debug.print("{s}\n", .{@errorName(err)});
                                                } else |err| std.debug.print("{s}\n", .{@errorName(err)});
                                            } else {
                                                try conn.stream.writer().writeAll("HTTP/1.1 500 \r\nContent-Length: 0\r\nContent-Type: text/plain\r\n\r\n");
                                            }
                                        },
                                        2 => {
                                            // APPLICATION COMMAND response type
                                            var interaction_data = response_obj.root.Object.get("data").?.Object;
                                            var command_name = interaction_data.get("name").?.String;
                                            var guild_id = response_obj.root.Object.get("guild_id").?.String;
                                            if (std.mem.eql(u8, command_name, "test")) {
                                                try conn.stream.writer().writeAll("HTTP/1.1 200 \r\nContent-Length: 37\r\nContent-Type: application/json\r\n\r\n{\"type\":4,\"data\":{\"content\":\"hello\"}}");
                                            } else if (std.mem.eql(u8, command_name, "greet")) {
                                                try conn.stream.writer().writeAll("HTTP/1.1 200 \r\nContent-Length: 78\r\nContent-Type: application/json\r\n\r\n{\"type\":4,\"data\":{\"content\":\"hello, it me andy-chan. i make zig go brr! UwU\"}}");
                                            } else if (std.mem.eql(u8, command_name, "stats")) {
                                                var ssl: *openssl.SSL = undefined;
                                                var ctx: *openssl.SSL_CTX = openssl.SSL_CTX_new(openssl.TLS_client_method()).?;
                                                var sbio = openssl.BIO_new_ssl_connect(ctx);
                                                _ = openssl.BIO_get_ssl(sbio, &ssl);
                                                _ = openssl.BIO_set_conn_hostname(sbio, "discord.com:443");
                                                var res = openssl.BIO_do_connect(sbio);
                                                if (res == 1) {
                                                    var buff_format: [1000]u8 = undefined;
                                                    var formatted = try std.fmt.bufPrintZ(
                                                        &buff_format,
                                                        "GET /api/v10/guilds/{s}/members?limit=1000 HTTP/1.1\r\nUser-Agent: curl/7.85.0\r\nHost: discord.com\r\nAccept: */*\r\nAuthorization: Bot {s}\r\n\r\n",
                                                        .{ guild_id, std.os.getenv("access_token").? },
                                                    );
                                                    var sent_puts = openssl.BIO_puts(sbio, @ptrCast([*c]const u8, formatted));
                                                    if (sent_puts > 0) {
                                                        std.debug.print("IN\n", .{});
                                                        var header_map = std.StringHashMap([]const u8).init(alloc);
                                                        defer header_map.deinit();
                                                        headers_read_size = try utils.read_header_openssl(&headers_buffer, sbio);
                                                        var header_msg_size = utils.parse_http_message(headers_buffer[0..headers_read_size], &header_map);
                                                        if (header_msg_size) |parsed_header_msg_size| {
                                                            if (header_map.get("transfer-encoding")) |_| {
                                                                // TAKE CARE OF CHUNKED ENCODED BODY
                                                                var response_body_initial = headers_buffer[parsed_header_msg_size..headers_read_size];
                                                                var chunk_body = try utils.handle_chunks(alloc, sbio, response_body_initial);
                                                                defer alloc.free(chunk_body);
                                                                std.debug.print("chunk body: {s}\n", .{chunk_body});
                                                                try conn.stream.writer().writeAll("HTTP/1.1 200 \r\nContent-Length: 78\r\nContent-Type: application/json\r\n\r\n{\"type\":4,\"data\":{\"content\":\"hello, it me andy-chan. i make zig go brr! UwU\"}}");
                                                            }
                                                        } else |err| std.debug.print("{s}\n", .{@errorName(err)});
                                                    }
                                                }
                                                openssl.BIO_free_all(sbio);
                                            }
                                        },
                                        3 => {},
                                        4 => {},
                                        5 => {},
                                        else => {},
                                    }
                                }
                            } else {
                                try conn.stream.writer().writeAll("HTTP/1.1 200 \r\nContent-Length: 0\r\n\r\n");
                            }
                        }
                    }
                }
            } else |err| std.debug.print("{s}\n", .{@errorName(err)});
        }
        conn.stream.close();
    }
}

test "utils" {
    _ = utils;
}

test "handle chunks" {
    var testing_alloc = std.testing.allocator;
    var ssl: *openssl.SSL = undefined;
    var ctx: *openssl.SSL_CTX = openssl.SSL_CTX_new(openssl.TLS_client_method()).?;
    var sbio = openssl.BIO_new_ssl_connect(ctx);
    _ = openssl.BIO_get_ssl(sbio, &ssl);
    _ = openssl.BIO_set_conn_hostname(sbio, "discord.com:443");
    var res = openssl.BIO_do_connect(sbio);
    try std.testing.expect(res == 1);
    var buff_format: [2000]u8 = undefined;
    var formatted = try std.fmt.bufPrintZ(
        &buff_format,
        "GET /api/v10/guilds/{s}/members?limit=1000 HTTP/1.1\r\nUser-Agent: curl/7.85.0\r\nHost: discord.com\r\nAccept: */*\r\nAuthorization: Bot {s}\r\n\r\n",
        .{ std.os.getenv("server_id").?, std.os.getenv("access_token").? },
    );
    var sent_size = openssl.BIO_puts(sbio, @ptrCast([*c]const u8, formatted));
    if (sent_size > 0) {
        var headers_buffer: [20000]u8 = undefined;
        var header_map = std.StringHashMap([]const u8).init(testing_alloc);
        defer header_map.deinit();
        var headers_read_size = try utils.read_header_openssl(&headers_buffer, sbio);
        var header_msg_size = utils.parse_http_message(headers_buffer[0..headers_read_size], &header_map);
        if (header_msg_size) |parsed_header_msg_size| {
            try std.testing.expect(header_map.get("transfer-encoding") != null);
            if (header_map.get("transfer-encoding")) |_| {
                // TAKE CARE OF CHUNKED ENCODED BODY
                var response_body_initial = headers_buffer[parsed_header_msg_size..headers_read_size];
                if (response_body_initial.len > 0) {
                    var chunk_body = try utils.handle_chunks(testing_alloc, sbio, response_body_initial);
                    try std.testing.expect(chunk_body.len > 0);
                    try std.testing.expect(std.json.validate(chunk_body) == false);
                }
            }
        } else |err| std.debug.print("{s}\n", .{@errorName(err)});
    }
    openssl.BIO_free_all(sbio);
}
