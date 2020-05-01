const std = @import("std");

inline fn long_compression_offset(data: []const u8, pos: *u32) !u32 {
    const byte = data[pos.*];
    pos.* += 1;

    return switch (byte) {
        0x00 => blk: {
            var total: u32 = 0xff;
            while (pos.* < data.len) : (pos.* += 1) {
                switch (data[pos.*]) {
                    0x00 => total += 0xff,
                    else => {
                        total += data[pos.*];
                        break :blk total;
                    },
                }
            }
            break :blk error.Malformed;
        },
        else => byte,
    };
}

inline fn literal_length(data: []const u8, pos: *u32) !u32 {
    const byte = data[pos.*];
    pos.* += 1;

    return switch (byte) {
        0x00 => blk: {
            var total: u32 = 0x0f;
            while (pos.* < data.len) : (pos.* += 1) {
                switch (data[pos.*]) {
                    0x00 => total += 0xff,
                    else => {
                        total += data[pos.*];
                        break :blk (total + 3);
                    },
                }
            }
            break :blk error.Malformed;
        },
        0x01...0x0f => byte + 3,
        else => blk: {
            pos.* -= 1;
            break :blk 0;
        },
    };
}

inline fn two_byte_offset(data: []const u8, pos: *u32, offset: *u32, count: *u32) !void {
    const byte1 = data[pos.*];
    const byte2 = data[pos.* + 1];
    pos.* += 2;

    offset.* = (byte1 >> 2) | (byte2 << 6);
    count.* = byte1 & 0x03;

    if (count.* == 0) {
        count.* = try literal_length(data, pos);
    }
}

pub fn decompress(comp_data: []const u8, decompressed_size: u32, alloc: *std.mem.Allocator) ![]u8 {
    var data = try alloc.alloc(u8, decompressed_size);
    errdefer alloc.free(data);

    var comp_pos: u32 = 0;
    var decomp_pos: u32 = 0;

    var literal_count = try literal_length(comp_data, &comp_pos);

    // Copy the initial uncompressed literal
    std.mem.copy(u8, data[0..literal_count], comp_data[0..literal_count]);
    comp_pos += literal_count;
    decomp_pos += literal_count;

    var comp_bytes: u32 = 0;
    var comp_offset: u32 = 0;

    while (comp_pos < comp_data.len and decomp_pos < decompressed_size) {
        const opcode = comp_data[comp_pos];
        comp_pos += 1;

        switch (opcode) {
            0x00...0x0F => return error.Malformed,
            0x10 => {
                comp_bytes = (try long_compression_offset(comp_data, &comp_pos)) + 9;
                try two_byte_offset(comp_data, &comp_pos, &comp_offset, &literal_count);
                comp_offset += 0x3fff;
            },
            0x11 => {
                if (decomp_pos != decompressed_size) return error.Malformed;
                return data;
            },
            0x12...0x1f => {
                comp_bytes = (opcode & 0x0f) + 2;
                try two_byte_offset(comp_data, &comp_pos, &comp_offset, &literal_count);
                comp_offset += 0x3fff;
            },
            0x20 => {
                comp_bytes = (try long_compression_offset(comp_data, &comp_pos)) + 0x21;
                try two_byte_offset(comp_data, &comp_pos, &comp_offset, &literal_count);
            },
            0x21...0x3f => {
                comp_bytes = opcode - 0x1e;
                try two_byte_offset(comp_data, &comp_pos, &comp_offset, &literal_count);
            },
            0x40...0xff => {
                comp_bytes = ((opcode & 0xf0) >> 4) - 1;

                const opcode2 = comp_data[comp_pos];
                comp_pos += 1;

                comp_offset = (opcode2 << 2) | ((opcode & 0x0c) >> 2);
                literal_count = switch (opcode & 0x03) {
                    0 => try literal_length(comp_data, &comp_pos),
                    else => opcode & 0x03,
                };
            },
        }

        // Copy compressed data
        if (comp_bytes + decomp_pos > decompressed_size) return error.Malformed;
        std.mem.copy(u8, data[decomp_pos..][0..comp_bytes], data[decomp_pos - comp_offset - 1 ..][0..comp_bytes]);
        decomp_pos += comp_bytes;

        // Copy uncompressed data
        if (literal_count + decomp_pos > decompressed_size or literal_count + comp_pos > comp_data.len) return error.Malformed;
        std.mem.copy(u8, data[decomp_pos..][0..literal_count], comp_data[comp_pos..][0..literal_count]);
        decomp_pos += literal_count;
        comp_pos += literal_count;
    }

    if (comp_pos < comp_data.len) {
        for (comp_data[comp_pos..]) |op| {
            if (op != 0x00 and op != 0x11) return error.Malformed;
        }
        return data;
    }

    return data;
}
