const std = @import("std");
const main = @import("main.zig");
const HTTP_Parse_Err = error{
    InvalidHttpMessage,
    ChunkLengthTooBig,
};
pub fn read_header_openssl(buff: []u8, sbio: ?*main.openssl.BIO) !usize {
    var bytes_read = main.openssl.BIO_read(sbio, @ptrCast(?*anyopaque, buff), @intCast(c_int, buff.len));
    while (!std.mem.containsAtLeast(u8, buff[0..@intCast(usize, bytes_read)], 1, "\r\n\r\n") and bytes_read > 0) {
        bytes_read += main.openssl.BIO_read(sbio, @ptrCast(?*anyopaque, buff[@intCast(usize, bytes_read)..]), @intCast(c_int, buff.len));
    }
    return @intCast(usize, bytes_read);
}
pub fn get_chunk_size(buff: []const u8) !usize {
    if (buff.len == 0) return 0;
    var size: usize = 0;
    for (buff) |_, index| {
        if (buff[index] == ';' or buff[index] == '\r') {
            var idx: usize = 0;
            while (idx < index) {
                if (idx % 2 != 0 and idx + 1 < index) {
                    switch (buff[idx]) {
                        '0'...'9' => size += @shlExact(
                            @as(usize, buff[idx] - '0'),
                            @truncate(u6, 8 * ((index - 1 - idx) / 2) + 4),
                        ),
                        'a'...'f' => size += @shlExact(
                            @as(usize, 10 + (buff[idx] - 'a')),
                            @truncate(
                                u6,
                                8 * ((index - 1 - idx) / 2) + 4,
                            ),
                        ),
                        else => {},
                    }
                    switch (buff[idx + 1]) {
                        '0'...'9' => size += @shlExact(
                            @as(usize, buff[idx + 1] - '0'),
                            @truncate(
                                u6,
                                8 * ((index - 1 - (idx + 1)) / 2),
                            ),
                        ),
                        'a'...'f' => size += @shlExact(
                            @as(usize, 10 + (buff[idx + 1] - 'a')),
                            @truncate(
                                u6,
                                8 * ((index - 1 - (idx + 1)) / 2),
                            ),
                        ),
                        else => {},
                    }
                    idx += 2;
                } else {
                    switch (buff[idx]) {
                        '0'...'9' => size += @shlExact(
                            @as(usize, buff[idx] - '0'),
                            @truncate(
                                u6,
                                8 * ((index - 1 - idx) / 2),
                            ),
                        ),
                        'a'...'f' => size += @shlExact(
                            @as(usize, 10 + (buff[idx] - 'a')),
                            @truncate(
                                u6,
                                8 * ((index - 1 - idx) / 2),
                            ),
                        ),
                        else => {},
                    }
                    idx += 1;
                }
            }
            break;
        }
    }
    return size;
}
pub fn handle_chunks(alloc: std.mem.Allocator, sbio: ?*main.openssl.BIO, initial_buff: []u8) ![]u8 {
    var chunked_bodies = std.ArrayList(u8).init(alloc);
    defer chunked_bodies.deinit();
    var read_buffer: [10000]u8 = undefined;
    if (initial_buff.len > 0) {
        try chunked_bodies.appendSlice(initial_buff[0..]);
    }
    var chunked_idx: usize = 0;
    while (true) {
        // get the first crlf (after 0 or more chunks) which has the chunk size
        // this could also be the last-chunk
        while (std.mem.indexOf(u8, chunked_bodies.items[chunked_idx..], "\r\n") == null) {
            var bytes_read = main.openssl.BIO_read(sbio, @ptrCast(?*anyopaque, &read_buffer), read_buffer.len);
            if (bytes_read > 0) {
                try chunked_bodies.appendSlice(read_buffer[0..@intCast(usize, bytes_read)]);
            }
        }
        // getting the index of the crlf
        var current_crlf = std.mem.indexOf(u8, chunked_bodies.items[chunked_idx..], "\r\n");
        if (current_crlf) |crlf| {
            var actual_crlf = chunked_idx + crlf + 2;
            // checking the parsed_size to see if it is 0 or not
            var parsed_size = try get_chunk_size(chunked_bodies.items[chunked_idx..actual_crlf]);
            if (parsed_size > 0) {
                // getting the next crlf which means the end of the chunk_data part
                var next_crlf_res = std.mem.indexOf(u8, chunked_bodies.items[actual_crlf..], "\r\n");
                while (next_crlf_res == null) {
                    var bytes_read = main.openssl.BIO_read(sbio, @ptrCast(?*anyopaque, &read_buffer), read_buffer.len);
                    if (bytes_read > 0) {
                        try chunked_bodies.appendSlice(read_buffer[0..@intCast(usize, bytes_read)]);
                    }
                    next_crlf_res = std.mem.indexOf(u8, chunked_bodies.items[actual_crlf..], "\r\n");
                }
                // we move the idx "pointer" to the end of the crlf
                // and continue the outer loop
                if (next_crlf_res) |next_crlf| {
                    chunked_idx = next_crlf + 2;
                }
            } else {
                // if parsed_size is 0, then we break because there will not be anymore chunks
                break;
            }
        }
    }
    // TODO: process chunked bytes and get the actual chunk data and parse into JSON
    return chunked_bodies.items;
}

pub fn read_header(buff: []u8, stream: std.net.Stream) !usize {
    var headers_read_size: usize = try stream.reader().read(buff[0..]);
    while (!std.mem.containsAtLeast(u8, buff[0..headers_read_size], 1, "\r\n\r\n") and headers_read_size > 0) {
        headers_read_size += try stream.reader().read(buff[headers_read_size..]);
    }
    return headers_read_size;
}

pub fn parse_http_message(buff: []u8, map: *std.StringHashMap([]const u8)) !usize {
    var end = std.mem.indexOf(u8, buff, "\r\n\r\n");
    if (end) |end_of_http_msg| {
        var newline_start_line = std.mem.indexOf(u8, buff[0..end_of_http_msg], "\r\n");
        var first_space = std.mem.indexOf(u8, buff[0..end_of_http_msg], " ");
        if (first_space) |fs| {
            try map.put("method", buff[0..fs]);
            if (newline_start_line) |ns| {
                try map.put("request-target", buff[fs + 1 .. ns]);
                var index: usize = ns + 2;
                while (index < end_of_http_msg) {
                    var key_end = std.mem.indexOf(u8, buff[index .. end_of_http_msg + 4], ":");
                    var crlf = std.mem.indexOf(u8, buff[index .. end_of_http_msg + 4], "\r\n");
                    if (key_end) |ke| {
                        var temp_ke = ke + index;
                        if (crlf) |ne| {
                            var temp_ne = ne + index;
                            var key = buff[index..temp_ke];
                            toLower(key);
                            var value = std.mem.trim(u8, buff[temp_ke + 1 .. temp_ne], " \r\n");
                            try map.put(key, value);
                            index = temp_ne + 2;
                        } else {
                            std.debug.print("no crlf: {s}\n", .{buff[index..end_of_http_msg]});
                            break;
                        }
                    } else {
                        std.debug.print("no key_end: {s}\n", .{buff[index..end_of_http_msg]});
                        break;
                    }
                }
                return end_of_http_msg + 4;
            }
        }
    }
    return HTTP_Parse_Err.InvalidHttpMessage;
}

pub fn check_newline_carriage_return(in: []u8) void {
    for (in) |chr| {
        if (chr == '\r' or chr == '\n') {
            @panic("carriage return or newline in timestamp_body");
        }
    }
}
pub fn toLower(str: []u8) void {
    for (str) |*chr| {
        if (chr.* >= 'A' and chr.* <= 'Z') {
            chr.* += 32;
        }
    }
}
pub fn parseInt(str: []const u8) usize {
    var res: usize = 0;
    for (str) |chr, idx| {
        res += (chr - '0') * (std.math.pow(u16, 10, @intCast(u16, str.len - 1 - idx)));
    }
    return res;
}
const HexConvertErr = error{InvalidHexString};
pub fn fromHex(alloc: std.mem.Allocator, hexStr: []const u8) ![]u8 {
    // 2 because hex string shows each byte two characters
    var res = try alloc.alloc(u8, hexStr.len / 2);
    for (res) |*loc| {
        loc.* = 0;
    }
    var idx_hexStr: usize = 0;
    var idx_res: usize = 0;
    while (idx_hexStr + 1 < hexStr.len) {
        var firstbyte: u8 = hexStr[idx_hexStr];
        var secondbyte: u8 = hexStr[idx_hexStr + 1];
        if (firstbyte >= '0' and firstbyte <= '9') {
            res[idx_res] |= (firstbyte - '0') << 4;
        } else if (firstbyte >= 'a' and firstbyte <= 'f') {
            res[idx_res] |= (10 + (firstbyte - 'a')) << 4;
        } else {
            return HexConvertErr.InvalidHexString;
        }
        if (secondbyte >= '0' and secondbyte <= '9') {
            res[idx_res] |= (secondbyte - '0');
        } else if (secondbyte >= 'a' and secondbyte <= 'f') {
            res[idx_res] |= (10 + (secondbyte - 'a'));
        } else {
            return HexConvertErr.InvalidHexString;
        }
        idx_hexStr += 2;
        idx_res += 1;
    }
    return res;
}

test "fromHex: signature" {
    var slice = try fromHex(
        std.testing.allocator,
        "d86906c229e9682014db13e29bb9d213739f95a3bdd3f58e08ff45ac468f27a836b34396b71b98b2b64df3092f6b2f527da0570772e955c83d4d95aeaa0a360e",
    );
    defer std.testing.allocator.free(slice);
    var correct = [_]u8{
        216,
        105,
        6,
        194,
        41,
        233,
        104,
        32,
        20,
        219,
        19,
        226,
        155,
        185,
        210,
        19,
        115,
        159,
        149,
        163,
        189,
        211,
        245,
        142,
        8,
        255,
        69,
        172,
        70,
        143,
        39,
        168,
        54,
        179,
        67,
        150,
        183,
        27,
        152,
        178,
        182,
        77,
        243,
        9,
        47,
        107,
        47,
        82,
        125,
        160,
        87,
        7,
        114,
        233,
        85,
        200,
        61,
        77,
        149,
        174,
        170,
        10,
        54,
        14,
    };
    try std.testing.expect(slice.len == std.mem.len(&correct));
    for (slice) |byte, idx| {
        try std.testing.expect(byte == correct[idx]);
    }
}

test "fromHex: signature2" {
    var slice = try fromHex(
        std.testing.allocator,
        "876bdbe52418099d2de1793eb30877302de79f905f0129ce7b096793e6ca544f66b2c03d9b5e5d7d1b68dd3bc4a214be99bc4a117bdfecb1b39f464e53ab830f",
    );
    defer std.testing.allocator.free(slice);
    var correct = [_]u8{
        135,
        107,
        219,
        229,
        36,
        24,
        9,
        157,
        45,
        225,
        121,
        62,
        179,
        8,
        119,
        48,
        45,
        231,
        159,
        144,
        95,
        1,
        41,
        206,
        123,
        9,
        103,
        147,
        230,
        202,
        84,
        79,
        102,
        178,
        192,
        61,
        155,
        94,
        93,
        125,
        27,
        104,
        221,
        59,
        196,
        162,
        20,
        190,
        153,
        188,
        74,
        17,
        123,
        223,
        236,
        177,
        179,
        159,
        70,
        78,
        83,
        171,
        131,
        15,
    };
    try std.testing.expect(std.mem.len(correct) == slice.len);
    for (correct) |byte, idx| {
        try std.testing.expect(byte == slice[idx]);
    }
}

test "toLower" {
    var str = [_]u8{ 'J', 'A', 'S', 'O', 'N' };
    toLower(str[0..]);
    try std.testing.expect(std.mem.eql(u8, str[0..], "jason"));
}

test "parse http message" {
    var alloc = std.testing.allocator;
    var msg: []const u8 = "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
    var msg_copy = try alloc.alloc(u8, msg.len);
    defer alloc.free(msg_copy);
    std.mem.copy(u8, msg_copy, msg);
    var map = std.StringHashMap([]const u8).init(alloc);
    defer map.deinit();
    var msg_size = try parse_http_message(msg_copy, &map);
    try std.testing.expect(msg_size == msg.len);
    try std.testing.expect(map.get("content-type") != null);
    var content_type = map.get("content-type").?;
    try std.testing.expect(std.mem.eql(u8, content_type, "application/json"));
}

test "parse chunk size" {
    var parsed_size = try get_chunk_size("36f4\r\n");
    var parsed_size2 = try get_chunk_size("363\r\n");
    try std.testing.expect(parsed_size == 0x36f4);
    try std.testing.expect(parsed_size2 == 0x363);
}
