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
                                    defer response_obj.deinit();
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
                                                    var buff_format: [2000]u8 = undefined;
                                                    var formatted = try std.fmt.bufPrintZ(
                                                        &buff_format,
                                                        "GET /api/v10/guilds/{s}/members?limit=1000 HTTP/1.1\r\nUser-Agent: curl/7.85.0\r\nHost: discord.com\r\nAccept: */*\r\nAuthorization: Bot {s}\r\n\r\n",
                                                        .{ guild_id, std.os.getenv("access_token").? },
                                                    );
                                                    var sent_puts = openssl.BIO_puts(sbio, @ptrCast([*c]const u8, formatted));
                                                    if (sent_puts > 0) {
                                                        var header_map = std.StringHashMap([]const u8).init(alloc);
                                                        defer header_map.deinit();
                                                        headers_read_size = try utils.read_header_openssl(&headers_buffer, sbio);
                                                        var header_msg_size = utils.parse_http_message(headers_buffer[0..headers_read_size], &header_map);
                                                        if (header_msg_size) |parsed_header_msg_size| {
                                                            if (header_map.get("transfer-encoding")) |_| {
                                                                // TAKE CARE OF CHUNKED ENCODED BODY
                                                                var response_body_initial = headers_buffer[parsed_header_msg_size..headers_read_size];
                                                                var chunk_data_str = try utils.handle_chunks(alloc, sbio, response_body_initial);
                                                                defer alloc.free(chunk_data_str);
                                                                if (std.json.validate(chunk_data_str)) {
                                                                    var parser2 = std.json.Parser.init(alloc, false);
                                                                    defer parser2.deinit();
                                                                    var member_list_json = try parser2.parse(chunk_data_str);
                                                                    defer member_list_json.deinit();
                                                                    var member_obj = member_list_json.root.Array.items;
                                                                    var join_dates = std.ArrayList([]const u8).init(alloc);
                                                                    defer join_dates.deinit();
                                                                    for (member_obj) |mem_obj| {
                                                                        try join_dates.append(mem_obj.Object.get("joined_at").?.String);
                                                                    }
                                                                    var timestamp = std.time.timestamp();
                                                                    var joins_last_year: usize = 0;
                                                                    var joins_last_30_days: usize = 0;
                                                                    var joins_last_1_day: usize = 0;
                                                                    for (join_dates.items) |join_date_str| {
                                                                        var date_slice = std.mem.indexOf(u8, join_date_str, "T");
                                                                        if (date_slice) |ds_last_idx| {
                                                                            var splitIter = std.mem.split(u8, join_date_str[0..ds_last_idx], "-");
                                                                            if (splitIter.next()) |yr| {
                                                                                if (splitIter.next()) |mnth| {
                                                                                    if (splitIter.next()) |day| {
                                                                                        var yr_num = utils.parseInt(yr);
                                                                                        var mnth_num = utils.parseInt(mnth);
                                                                                        var day_num = utils.parseInt(day);
                                                                                        const s_per_yr: usize = std.time.s_per_day * 365;
                                                                                        const s_per_month: usize = std.time.s_per_day * 30;
                                                                                        var yrs_since_epoch_for_input_yr = yr_num - 1970;
                                                                                        var s_since_epoch_input_yr =
                                                                                            @intCast(i64, yrs_since_epoch_for_input_yr * s_per_yr + mnth_num * s_per_month + day_num * std.time.s_per_day);

                                                                                        if (try std.math.absInt(timestamp - s_since_epoch_input_yr) <= s_per_yr) {
                                                                                            joins_last_year += 1;
                                                                                        }

                                                                                        if (try std.math.absInt(timestamp - s_since_epoch_input_yr) <= s_per_month) {
                                                                                            joins_last_30_days += 1;
                                                                                        }

                                                                                        if (try std.math.absInt(timestamp - s_since_epoch_input_yr) <= std.time.s_per_day) {
                                                                                            joins_last_1_day += 1;
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    var buff_format_data: [10000]u8 = undefined;
                                                                    var formatted_data = try std.fmt.bufPrintZ(
                                                                        &buff_format_data,
                                                                        "{{\"type\":4,\"data\":{{\"content\":\"```joins within last year: {}\\njoins within last 30 days: {}\\njoins within last 1 day: {}\\ntotal joins: {}```\"}}}}",
                                                                        .{ joins_last_year, joins_last_30_days, joins_last_1_day, join_dates.items.len },
                                                                    );
                                                                    var buff_format_response: [10000]u8 = undefined;
                                                                    var formatted_response = try std.fmt.bufPrintZ(
                                                                        &buff_format_response,
                                                                        "HTTP/1.1 200 \r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{s}",
                                                                        .{
                                                                            formatted_data.len,
                                                                            formatted_data,
                                                                        },
                                                                    );
                                                                    try conn.stream.writer().writeAll(formatted_response);
                                                                } else {
                                                                    std.debug.print("chunk parsing failed and json validating returned false\n", .{});
                                                                }
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
                    var chunk_data_str = try utils.handle_chunks(testing_alloc, sbio, response_body_initial);
                    defer testing_alloc.free(chunk_data_str);
                    try std.testing.expect(chunk_data_str.len > 0);
                    try std.testing.expect(std.json.validate(chunk_data_str) == true);
                    var parser = std.json.Parser.init(testing_alloc, false);
                    defer parser.deinit();
                    var json = try parser.parse(chunk_data_str);
                    defer json.deinit();
                    var member_obj = json.root.Array.items;
                    for (member_obj) |item| {
                        try std.testing.expect(item.Object.get("joined_at").?.String.len > 0);
                    }
                    var join_dates = std.ArrayList([]const u8).init(alloc);
                    defer join_dates.deinit();
                    for (member_obj) |mem_obj| {
                        try join_dates.append(mem_obj.Object.get("joined_at").?.String);
                    }
                    var timestamp = std.time.timestamp();
                    var joins_last_year: usize = 0;
                    var joins_last_30_days: usize = 0;
                    var joins_last_1_day: usize = 0;
                    for (join_dates.items) |join_date_str| {
                        var date_slice = std.mem.indexOf(u8, join_date_str, "T");
                        if (date_slice) |ds_last_idx| {
                            var splitIter = std.mem.split(u8, join_date_str[0..ds_last_idx], "-");
                            if (splitIter.next()) |yr| {
                                if (splitIter.next()) |mnth| {
                                    if (splitIter.next()) |day| {
                                        var yr_num = utils.parseInt(yr);
                                        var mnth_num = utils.parseInt(mnth);
                                        var day_num = utils.parseInt(day);
                                        const s_per_yr: usize = std.time.s_per_day * 365;
                                        const s_per_month: usize = std.time.s_per_day * 30;
                                        var yrs_since_epoch_for_input_yr = yr_num - 1970;
                                        var s_since_epoch_input_yr =
                                            @intCast(i64, yrs_since_epoch_for_input_yr * s_per_yr + mnth_num * s_per_month + day_num * std.time.s_per_day);

                                        if (try std.math.absInt(timestamp - s_since_epoch_input_yr) <= s_per_yr) {
                                            joins_last_year += 1;
                                        }

                                        if (try std.math.absInt(timestamp - s_since_epoch_input_yr) <= s_per_month) {
                                            joins_last_30_days += 1;
                                        }

                                        if (try std.math.absInt(timestamp - s_since_epoch_input_yr) <= std.time.s_per_day) {
                                            joins_last_1_day += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    std.debug.print("\nyr: {} mnth: {} day: {}\n", .{ joins_last_year, joins_last_30_days, joins_last_1_day });
                }
            }
        } else |err| std.debug.print("{s}\n", .{@errorName(err)});
    }
    openssl.BIO_free_all(sbio);
}
