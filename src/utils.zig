const std = @import("std");

pub fn check_newline_carriage_return(in: []u8) void {
    for (in) |chr| {
        if (chr == '\r' or chr == '\n') {
            @panic("carriage return or newline in timestamp_body");
        }
    }
}
