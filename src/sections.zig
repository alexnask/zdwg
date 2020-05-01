pub const SectionPage = struct {
    const Type = enum(u32) {
        section_page_map = 0x41630e3b,
        section_map = 0x4163003b,
    };

    type: Type,
    decompressed_data_size: u32,
    compressed_data_size: u32,
    // Must be 0x02
    compression_type: u32,
    checksum: u32,

    // TODO: fn compute_checksum
};
