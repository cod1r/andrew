const std = @import("std");
const main = @import("main.zig");
const HTTP_Parse_Err = error{
    InvalidHttpMessage,
    ChunkLengthTooBig,
};
pub fn read_header_openssl(buff: []u8, sbio: ?*main.openssl.BIO) !usize {
    var bytes_read = main.openssl.BIO_read(sbio, @ptrCast(?*anyopaque, buff), @intCast(c_int, buff.len));
    while (!containsStr(buff[0..@intCast(usize, bytes_read)], "\r\n\r\n") and bytes_read > 0) {
        bytes_read += main.openssl.BIO_read(sbio, @ptrCast(?*anyopaque, buff), @intCast(c_int, buff.len));
    }
    return @intCast(usize, bytes_read);
}
pub fn get_chunk_size(buff: []u8) !usize {
    if (buff.len == 0) return 0;
    var size: usize = 0;
    for (buff) |_, index| {
        if (buff[index] == ';' or (index + 1 < buff.len and buff[index] == '\r' and buff[index + 1] == '\n')) {
            var idx: usize = 0;
            while (idx < index) {
                switch (buff[idx]) {
                    '0'...'9' => size += (buff[idx] - '0') * std.math.pow(usize, 10, (buff.len - 1 - idx) / 2),
                    'a'...'f' => size += (10 + (buff[idx] - 'a')) * std.math.pow(usize, 10, (buff.len - 1 - idx) / 2),
                    else => {},
                }
                switch (buff[idx + 1]) {
                    '0'...'9' => size += (buff[idx + 1] - '0') * std.math.pow(usize, 10, (buff.len - 1 - idx) / 2),
                    'a'...'f' => size += (10 + (buff[idx + 1] - 'a')) * std.math.pow(usize, 10, (buff.len - 1 - idx) / 2),
                    else => {},
                }
            }
            break;
        }
    }
    return size;
}
pub fn handle_chunks(alloc: std.mem.Allocator, sbio: ?*main.openssl.BIO, initial_buff: []u8) ![]u8 {
    var chunked_bodies = std.ArrayList(u8).init(alloc);
    var read_buffer: [10000]u8 = undefined;
    if (initial_buff.len > 0) {
        try chunked_bodies.appendSlice(initial_buff[0..]);
    }
    var chunked_idx: usize = 0;
    while (true) {
        // get the first crlf which has the chunk size
        // this could also be the last-chunk
        while (std.mem.indexOf(u8, chunked_bodies.items[chunked_idx..], "\r\n") == null) {
            var bytes_read = main.openssl.BIO_read(sbio, @ptrCast(?*anyopaque, &read_buffer), read_buffer.len);
            if (bytes_read > 0) {
                try chunked_bodies.appendSlice(read_buffer[0..@intCast(usize, bytes_read)]);
            }
        }
        // parse the chunk size
        // if 0, then we break out of the while loop
        var chunk_data_size: usize = 0;
        if (std.mem.indexOf(u8, chunked_bodies.items[0..], "\r\n")) |end_index| {
            var parsed_size = try get_chunk_size(chunked_bodies.items[0..end_index]);
            if (parsed_size > 0) {
                chunked_idx = end_index + 1;
                if (chunked_bodies.items.len - end_index > 1) {
                    parsed_size -= chunked_bodies.items.len - (end_index + 1);
                }
                chunk_data_size = parsed_size;
            } else {
                break;
            }
        }
        var prev_chunk_idx: usize = chunked_idx;
        // loop until chunk data size is 0 and we get another crlf indicating the end of the chunk data
        while (chunk_data_size > 0 and !std.mem.containsAtLeast(u8, chunked_bodies.items[prev_chunk_idx..], 1, "\r\n")) {
            var bytes_read = main.openssl.BIO_read(sbio, @ptrCast(?*anyopaque, &read_buffer), read_buffer.len);
            if (bytes_read > 0) {
                try chunked_bodies.appendSlice(read_buffer[0..@intCast(usize, bytes_read)]);
                prev_chunk_idx = chunked_idx;
                chunked_idx += @intCast(usize, bytes_read);
                chunk_data_size -= @intCast(usize, bytes_read);
            }
        }
    }
    // TODO: process chunked bytes and get the actual chunk data and parse into JSON
    return chunked_bodies.items;
}

pub fn read_header(buff: []u8, stream: std.net.Stream) !usize {
    var headers_read_size: usize = try stream.reader().read(buff[0..]);
    while (!containsStr(buff[0..headers_read_size], "\r\n\r\n") and headers_read_size > 0) {
        headers_read_size += try stream.reader().read(buff[headers_read_size..]);
    }
    return headers_read_size;
}

pub fn parse_http_message(buff: []u8, map: *std.StringHashMap([]u8)) !usize {
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
            var key = buff[index..key_end];
            toLower(key);

            var value_beginning: usize = key_end + 1;
            var value_end: usize = newline_value_end;
            if (buff[value_beginning] == ' ') value_beginning += 1;
            while (buff[value_end] == '\r' or buff[value_end] == ' ' or buff[value_end] == '\n') {
                value_end -= 1;
            }
            var value = buff[value_beginning .. value_end + 1];

            try map.put(key, value);
            index = newline_value_end + 1;
            read += (newline_value_end + 1 - read);
        } else if (key_end > index and newline_value_end <= key_end + 1) {
            var key = buff[index..key_end];
            toLower(key);

            var value_beginning: usize = key_end + 1;
            if (buff[value_beginning] == ' ') value_beginning += 1;
            var value = buff[value_beginning..buff.len];

            try map.put(key, value);
            index = buff.len;
            read += (buff.len - read);
        } else {
            break;
        }
    }
    return read;
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
pub fn containsStr(str: []const u8, target: []const u8) bool {
    var idx: usize = 0;
    while (idx + target.len <= str.len and str.len >= target.len) {
        if (std.mem.eql(u8, str[idx .. idx + target.len], target)) {
            return true;
        }
        idx += 1;
    }
    return false;
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

test "containsStr" {
    try std.testing.expect(containsStr("\r\n\r\n", "\r\n\r\n"));
    try std.testing.expect(containsStr("asdfasdfasdfasdfasdf\r\n\r\n", "\r\n\r\n"));
    try std.testing.expect(containsStr("asdfasdfasdfasdfasdf\r\n\r\nsdfasdfasdfasdfsdf", "\r\n\r\n"));
}

test "parse http message" {
    var alloc = std.testing.allocator;
    var msg: []const u8 = "POST / HTTP/1.1\r\nContent-Type: application/json\r\n";
    var msg_copy = try alloc.alloc(u8, msg.len);
    defer alloc.free(msg_copy);
    std.mem.copy(u8, msg_copy, msg);
    var map = std.StringHashMap([]u8).init(alloc);
    defer map.deinit();
    var msg_size = try parse_http_message(msg_copy, &map);
    try std.testing.expect(msg_size == msg.len);
    var content_type = map.get("content-type").?;
    try std.testing.expect(std.mem.eql(u8, content_type, "application/json"));
    var start_line = map.get("start_line").?;
    try std.testing.expect(std.mem.eql(u8, start_line, "POST / HTTP/1.1\r\n"));
}
