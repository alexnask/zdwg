const std = @import("std");

// Everything is little endian.

pub const ThreeBits = struct {
    value: u3,
};

// TODO: Parsing tests.
// 00 00000001 00000001 (short 257)
// 10 (0)
// 11 (256)
// 01 00001111 (15)
// 10 (0)
pub const BitShort = struct {
    pub const Flag = enum(u2) {
        i16 = 0b00,
        u8 = 0b01,
        @"0" = 0b10,
        @"256" = 0b11,
    };

    value: i16,
};

// TODO: Parsing tests.
// 00 00000001 00000001 00000000 00000000 (long 257)
// 10 (0)
// 01 00001111 (15)
// 10 (0)
pub const BitLong = struct {
    pub const Flag = enum(u2) {
        i32 = 0b00,
        u8 = 0b01,
        @"0" = 0b10,
    };

    value: i32,
};

pub const BitLongLong = struct {
    length: ThreeBits,
    value: [7]u8,
};

pub const BitDouble = struct {
    pub const Flag = enum(u2) {
        f64 = 0b00,
        @"1" = 0b01,
        @"0" = 0b10,
    };

    value: f64,
};

pub const ModularChars = struct {
    value: []u8,
};

pub const ModularShorts = struct {
    value: []u8,
};

pub const BitExtrusion = struct {
    pub const Flag = enum(u1) {
        ThreeBits = 0b0,
        @"1" = 0b1,
    };

    value: ThreeBits,
};

pub const BitThickness = struct {
    pub const Flag = enum(u1) {
        BitDouble = 0b0,
        @"0" = 0b1,
    };

    value: BitDouble,
};

pub const ColorCMC = struct {
    index: BitShort,
    rgb: BitLong,
    col: u8,
    name: VariableText,
};

pub const ObjectType = struct {
    pub const Flag = enum(u2) {
        u8 = 0b00,
        @"+ u8 496" = 0b01,
        u16 = 0b10,
    };

    value: u16,
};

pub const Handle = struct {
    pub const Code = enum(u4) {
        SoftOwnership = 2,
        HardOwnership = 3,
        SoftPointer = 4,
        HardPointer = 5,
        _,
    };

    code: Code,
    length: u4,
    value: [15]u8,
};

pub const VariableText = struct {
    length: BitShort,
    value: []u16,
};
