const std = @import("std");
const meta = std.meta;
const trait = meta.trait;
const TypeInfo = std.builtin.TypeInfo;

usingnamespace @import("types.zig");
usingnamespace @import("header.zig");
usingnamespace @import("sections.zig");
usingnamespace @import("compression.zig");

// TODO: Move those to utils.zig or something
fn structCast(comptime Res: type, arg: var) Res {
    const InT = @TypeOf(arg);
    if (comptime !trait.is(.Struct)(InT)) @compileError("Cannot struct cast from non struct type " ++ @typeName(InT));
    var res: Res = undefined;

    inline for (meta.fields(InT)) |field| {
        if (!@hasField(Res, field.name)) @compileError("Target struct " ++ @typeName(Res) ++ " does not have a '" ++ field.name ++ "' field.");

        @field(res, field.name) = @field(arg, field.name);
    }
    return res;
}

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

    const section_page_map = try parsePart(SystemSection, &bitstream);
    if (section_page_map.type != .section_page_map) return error.Malformed;
    if (section_page_map.compression_type != 0x02) return error.Malformed;

    std.debug.warn("Section page map: {}\n\n", .{section_page_map});

    try assertByteAligned(bitstream);
    const compressed_data = try getSlice(section_page_map.compressed_data_size, bitstream);

    const decompressed_data = try decompress(compressed_data, section_page_map.decompressed_data_size, alloc);
    defer alloc.free(decompressed_data);

    // std.debug.warn("Section page map data: {x}\n\n", .{decompressed_data});

    var section_map_page: PageInfo = undefined;

    // Parse the section page map decompressed data.
    {
        var section_page_map_bitstream = std.io.bitInStream(std.builtin.Endian.Little, std.io.fixedBufferStream(decompressed_data).inStream());
        var address: u32 = 0x100;
        var section_map_found: bool = false;

        // Iterate over page infos, we only keep the section map one for now.
        var i: u32 = 0;
        while (i < section_page_map.decompressed_data_size) {
            var page_info = structCast(PageInfo, try parsePart(struct { number: i32, size: u32 }, &section_page_map_bitstream));
            i += 8;

            page_info.address = address;

            if (page_info.number < 0) {
                try skipBytes(16, &section_page_map_bitstream);
                i += 16;
            }

            if (page_info.number == header_data.section_map_id) {
                section_map_found = true;
                section_map_page = page_info;
            }

            std.debug.warn("{}\n", .{page_info});
            address += page_info.size;
        }

        if (!section_map_found) return error.Malformed;
    }

    std.debug.warn("Section map page info: {}\n\n", .{section_map_page});

    // TODO: Address seems to be wrong... (bigger than filesize)
    // It appears that the first few page_infos are corrupted.
    try jumpToBytePos(section_map_page.address, &bitstream);
    const section_map = try parsePart(SystemSection, &bitstream);

    std.debug.warn("Section map: {}\n\n", .{section_map});
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
    try parseFile("test2.dwg", std.heap.page_allocator);
}

// The 2013 format is based mostly on the 2010 format.

// The file header, summary info, page map, section map, compression are the same as in R2004.

// The bit coding is the same as in R2010.

// Like the R2007 format, the data, strings and handles are separated in header and
// objects sections. The changes in the Header section are minor (only 2 added fields).

// A new data section was introduced, the data storage section (AcDb:AcDsPrototype_1b).
// At this moment (December 2012), this sections contains information about Acis data (regions, solids).
// See chapter 24 for more details about this section.

// Note that at the point of writing (22 March 2013) known valid values for acad maintenance version are 6
// and 8. The ODA currently writes value 8.

// TODO: slice.*: [N]T
// Can I simplify anything?
