const std = @import("std");

pub fn check_newline_carriage_return(in: []u8) void {
    for (in) |chr| {
        if (chr == '\r' or chr == '\n') {
            @panic("carriage return or newline in timestamp_body");
        }
    }
}

pub fn fromHex(alloc: std.mem.Allocator, hexStr: []u8) ![]u8 {
    var res = alloc.alloc(u8, hexStr.len / 4);
    _ = res;
}
