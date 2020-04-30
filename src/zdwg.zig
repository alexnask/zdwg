const std = @import("std");
const meta = std.meta;
const trait = meta.trait;

usingnamespace @import("header.zig");
usingnamespace @import("types.zig");

// TODO: Read the whole file into a buffer and use a stream to that.

fn parsePart(comptime T: type, bitstream: var) !T {
    var res: T = undefined;

    if (comptime trait.isUnsignedInt(T)) {
        res = try bitstream.readBitsNoEof(T, @typeInfo(T).Int.bits);
    } else if (comptime trait.isSignedInt(T)) {
        const info = @typeInfo(T);
        const UnsignedT = @Type(std.builtin.TypeInfo{ .Int = std.builtin.TypeInfo.Int{ .is_signed = false, .bits = info.Int.bits } });

        res = @bitCast(T, try bitstream.readBitsNoEof(UnsignedT, info.Int.bits));
    } else if (T == ThreeBits) {
        // This is a sequence of 1 to 3 bits. Keep reading bits until a zero bit is encountered or until the 3rd bit
        // is read, whatever comes first. Each time a bit is read, shift the previously read bits to the left. The
        // result is a number 0-7.
        var bit = try bitstream.readBitsNoEof(u1, 1);
        res.value = @intCast(u3, bit);
        if (bit == 0) return res;

        bit = try bitstream.readBitsNoEof(u1, 1);
        res.value = (res.value << 1) | bit;

        if (bit == 0) return res;
        bit = try bitstream.readBitsNoEof(u1, 1);
        res.value = (res.value << 1) | bit;
    } else if (comptime (trait.is(.Array)(T) and meta.Child(T) == u8)) {
        if ((try bitstream.read(res[0..])) != @typeInfo(T).Array.len) return error.Malformed;
    } else if (@hasDecl(T, "Flag")) {
        @compileError("TODO");
    } else {
        // TODO: Add an enum case (like for Handle.Code)
        inline for (meta.fields(T)) |field| {
            @field(res, field.name) = try parsePart(field.field_type, bitstream);
        }
    }

    return res;
}

fn skipBytes(comptime n: comptime_int, bitstream: var) !void {
    var buf: [n]u8 = undefined;
    if ((try bitstream.read(buf[0..])) != n) return error.Malformed;
}

pub fn parse(buf: []const u8) !void {
    var bitstream = std.io.bitInStream(std.builtin.Endian.Little, std.io.fixedBufferStream(buf).inStream());

    std.debug.warn("\nHeader struct size: {} bytes\n\n\n", .{@sizeOf(Header)});

    const header = try parsePart(Header, &bitstream);
    if (!std.mem.eql(u8, header.version_id[0..], "AC1027")) return error.UnsupportedVersion;

    std.debug.warn("Version: {}\nPreview address: {}\nApp version: {}\nApp maintenance version: {}\nCodepage: {}\nSecurity flags: {}\nSummary info address: {}\n" ++
        "VBA project address: {}\n", .{
        header.version_id,
        header.preview_address,
        header.app_version,
        header.app_maintenance_version,
        header.codepage,
        header.security_flags,
        header.summary_info_address,
        header.vba_project_address,
    });

    const decrypted_data = decryptHeaderEncryptedData(header.encrypted_data);
    // TODO: This segfaults (slicing the u8 array in the packed struct)
    // if (!std.mem.eql(u8, decrypted_data.file_id[0..11], "AcFssFcAJMB")) return error.WrongDecryptedFileID;
}

pub fn parseFile(path: []const u8, alloc: *std.mem.Allocator) !void {
    var buf: []u8 = undefined;

    {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const stat = try file.stat();
        if (stat.size == 0) return error.EmptyFile;

        buf = try alloc.alloc(u8, stat.size);
        errdefer alloc.free(buf);

        if ((try file.readAll(buf[0..])) != stat.size) return error.CouldNotReadFile;
    }

    defer alloc.free(buf);
    try parse(buf);
}

test "Parse a file" {
    try parseFile("test.dwg", std.heap.page_allocator);
}
