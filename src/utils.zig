const std = @import("std");

pub fn check_newline_carriage_return(in: []u8) void {
    for (in) |chr| {
        if (chr == '\r' or chr == '\n') {
            @panic("carriage return or newline in timestamp_body");
        }
    }
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
