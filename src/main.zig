const std = @import("std");

pub fn main() !void {
    var add = try std.net.Address.parseIp("127.0.0.1", 8000);
    var ss = std.net.StreamServer.init(.{});
    defer ss.deinit();
    try ss.listen(add);
    var conn = try ss.accept();
    var buff: [50000]u8 = undefined;
    var sent_size = try conn.stream.write("HTTP/2.0 200 \r\n");
    _ = sent_size;
    var read_size = try conn.stream.read(buff[0..]);
    std.debug.print("{s}\n", .{buff[0..read_size]});
}
