const std = @import("std");
const meta = std.meta;
const trait = meta.trait;
const TypeInfo = std.builtin.TypeInfo;

usingnamespace @import("header.zig");
usingnamespace @import("types.zig");

// TODO: Open issue, fix stdblib for comptime_int parseInteger/parseUnsigned
fn parseUnsigned(comptime digits: []const u8) !comptime_int {
    var x: comptime_int = 0;
    for (digits) |c| {
        const digit: comptime_int = switch (c) {
            '0'...'9' => c - '0',
            else => return raise.InvalidCharacter,
        };
        if (x != 0) x *= 10;
        x += digit;
    }

    return x;
}

fn parseFromFlag(comptime flag: []const u8, comptime ResType: type, bitstream: var) !ResType {
    // We have four cases here

    // We could have a u<N>, i<N> or f<N> flag
    if (flag[0] == 'u' or flag[0] == 'i' or flag[0] == 'f') {
        const maybe_bits = parseUnsigned(flag[1..]) catch -1;
        if (maybe_bits > 0) {
            const Type = switch (flag[0]) {
                'u' => @Type(TypeInfo{ .Int = .{ .is_signed = false, .bits = maybe_bits } }),
                'i' => @Type(TypeInfo{ .Int = .{ .is_signed = true, .bits = maybe_bits } }),
                'f' => @Type(TypeInfo{ .Float = .{ .bits = maybe_bits } }),
                else => unreachable,
            };

            return @as(ResType, try parsePart(Type, bitstream));
        }
    }
    // Or a literal flag.
    if (flag[0] >= '0' and flag[0] <= '9') {
        // TODO: We could collide with a legitimate -1 value...
        const literal_value = parseUnsigned(flag) catch -1;
        // We can also assign to a struct with a 'value' field.
        if (comptime trait.is(.Struct)(ResType)) {
            return ResType{ .value = literal_value };
        }
        return @as(ResType, literal_value);
    }
    // Or a flag of some other type
    inline for (meta.declarations(@import("types.zig"))) |decl| {
        if (comptime std.mem.eql(u8, decl.name, flag)) {
            return @as(ResType, try parsePart(decl.data.Type, bitstream));
        }
    }
    // Or a "+ <flag1> <flag2>" flag
    if (flag[0] == '+' and flag[1] == ' ') {
        comptime var i = 2;
        comptime while (flag[i] != ' ') : (i += 1) {};
        const res1 = try parseFromFlag(flag[2..i], ResType, bitstream);
        const res2 = try parseFromFlag(flag[i + 1 ..], ResType, bitstream);
        return res1 + res2;
    }
}

fn parsePart(comptime T: type, bitstream: var) !T {
    var res: T = undefined;

    if (comptime trait.isUnsignedInt(T)) {
        res = try bitstream.readBitsNoEof(T, @typeInfo(T).Int.bits);
    } else if (comptime trait.isSignedInt(T)) {
        const info = @typeInfo(T);
        const UnsignedT = @Type(TypeInfo{ .Int = .{ .is_signed = false, .bits = info.Int.bits } });

        res = @bitCast(T, try bitstream.readBitsNoEof(UnsignedT, info.Int.bits));
    } else if (comptime trait.is(.Float)(T)) {
        const info = @typeInfo(T);
        const UnsignedT = @Type(TypeInfo{ .Int = .{ .is_signed = false, .bits = info.Float.bits } });

        res = @bitCast(T, try bitstream.readBitsNoEof(UnsignedT, info.Float.bits));
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
        if (comptime !trait.is(.Enum)(T.Flag)) {
            @compileError(@typeName(T) ++ "." ++ @typeName(T.Flag) ++ " should be an enum.");
        }

        const flag_value = try parsePart(T.Flag, bitstream);

        inline for (meta.fields(T.Flag)) |field| {
            if (flag_value == @intToEnum(T.Flag, field.value)) {
                res.value = try parseFromFlag(field.name, @TypeOf(res.value), bitstream);
                return res;
            }
        }

        return error.InvalidFlag;
    } else if (comptime trait.is(.Enum)(T)) {
        const Integer = @TagType(T);
        res = @intToEnum(T, try parsePart(Integer, bitstream));
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

    std.debug.warn("Header: {}\n\n", .{header});

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
