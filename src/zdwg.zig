const std = @import("std");
const meta = std.meta;
const trait = meta.trait;
const TypeInfo = std.builtin.TypeInfo;

usingnamespace @import("types.zig");
usingnamespace @import("header.zig");
usingnamespace @import("sections.zig");
usingnamespace @import("compression.zig");

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

inline fn parseFromFlag(comptime flag: []const u8, comptime ResType: type, bitstream: var) !ResType {
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

inline fn parsePart(comptime T: type, bitstream: var) !T {
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
        // A "length" field indicates how many of value's elements to fill.
        // TODO: "length" must also be before "value" in the struct, check it somehow.
        const has_length = @hasField(T, "length");
        inline for (meta.fields(T)) |field| {
            if (has_length and comptime std.mem.eql(u8, field.name, "value")) {
                var i: usize = 0;
                const length_val = if (comptime trait.is(.Struct)(@TypeOf(res.length)))
                    res.length.value
                else
                    res.length;

                while (i < length_val) : (i += 1) {
                    res.value[i] = try parsePart(meta.Child(field.field_type), bitstream);
                }
            } else {
                @field(res, field.name) = try parsePart(field.field_type, bitstream);
            }
        }
    }

    return res;
}

inline fn skipBytes(comptime n: comptime_int, bitstream: var) !void {
    var buf: [n]u8 = undefined;
    if ((try bitstream.read(buf[0..])) != n) return error.Malformed;
}

inline fn jumpToBytePos(index: u64, bitstream: var) !void {
    bitstream.alignToByte();
    try bitstream.in_stream.context.seekTo(index);
}

// TODO: We may need a bit version
inline fn jumpByBytes(offset: i64, bitstream: var) !void {
    bitstream.alignToByte();
    try bitstream.in_stream.context.seekTo(bitstream.in_stream.context.pos + offset);
}

inline fn getSlice(len: usize, bitstream: var) ![]const u8 {
    const buf = bitstream.in_stream.context.buffer;
    const pos = bitstream.in_stream.context.pos;
    if (pos + len >= buf.len) return error.Malformed;
    return buf[pos..][0..len];
}

inline fn assertByteAligned(bitstream: var) !void {
    if (std.builtin.mode == .Debug) {
        if (bitstream.bit_buffer != 0 or bitstream.bit_count != 0) return error.Malformed;
    }
}

pub fn parse(buf: []const u8, alloc: *std.mem.Allocator) !void {
    var bitstream = std.io.bitInStream(std.builtin.Endian.Little, std.io.fixedBufferStream(buf).inStream());

    const header = try parsePart(Header, &bitstream);
    if (!std.mem.eql(u8, &header.version_id, "AC1027")) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, &header.magic_end_seq, &header_magic_end_seq)) return error.Malformed;

    std.debug.warn("\nHeader: {}\n\n", .{header});

    const header_data = decryptHeaderData(header.encrypted_header_data);
    std.debug.warn("Header decrypted data: {}\n\n", .{header_data});

    // TODO: #5104
    // if (!std.mem.eql(u8, &decrypted_data.file_id, "AcFssFcAJMB")) return error.WrongDecryptedFileID;

    try jumpToBytePos(header_data.section_page_map_address + 0x100, &bitstream);

    const section_page = try parsePart(SectionPage, &bitstream);
    if (section_page.type != .section_page_map) return error.Malformed;
    if (section_page.compression_type != 0x02) return error.Malformed;

    std.debug.warn("Section page map: {}\n\n", .{section_page});

    try assertByteAligned(bitstream);
    const compressed_data = try getSlice(section_page.compressed_data_size, bitstream);

    const decompressed_data = try decompress(compressed_data, section_page.decompressed_data_size, alloc);
    defer alloc.free(decompressed_data);

    std.debug.warn("Section page map data:\n{X}\n\n", .{decompressed_data});
}

// TODO: Return a DrawingFile struct.
// TODO: Check CRC checksums.
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
    try parse(buf, alloc);
}

test "Parse a file" {
    try parseFile("test.dwg", std.heap.page_allocator);
}
