pub const Header = struct {
    version_id: [6]u8,
    _unused1: [7]u8,
    preview_address: u32,
    app_version: u8,
    app_maintenance_version: u8,
    codepage: u16,
    _unused2: [3]u8,
    security_flags: u32,
    _unused3: [4]u8,
    summary_info_address: u32,
    vba_project_address: u32,
    _unused4: [4]u8,
    _unused5: [84]u8,
    encrypted_header_data: [108]u8,
    // TODO: Is this correct? Doc is confusing. (page 26 last 2 paragraphs)
    magic_end_seq: [20]u8,
};

pub const header_magic_end_seq = [_]u8{ 0xF8, 0x46, 0x6A, 0x04, 0x96, 0x73, 0x0E, 0xD9, 0x16, 0x2F, 0x67, 0x68, 0xD4, 0xF7, 0x4A, 0x4A, 0xD0, 0x57, 0x68, 0x76 };

const decryptionTable = block: {
    var seq: [108]u8 = undefined;
    var i = 108;
    var seed: u32 = 1;
    while (i > 0) : (i -= 1) {
        seed *%= 0x0343fd;
        seed +%= 0x269ec3;
        seq[108 - i] = @truncate(u8, seed >> 0x10);
    }
    break :block seq;
};

pub const HeaderData = packed struct {
    file_id: [11:0]u8,
    _unused1: [12]u8,
    root_tree_node_gap: u32,
    lowermost_left_tree_node_gap: u32,
    lowermost_right_tree_node_gap: u32,
    _unused2: [4]u8,
    last_section_page_id: u32,
    last_section_page_end_address: u64,
    second_header_data_address: u64,
    gap_amount: u32,
    section_page_amount: u32,
    _unused3: [12]u8,
    section_page_map_id: u32,
    section_page_map_address: u64,
    section_map_id: u32,
    section_page_array_size: u32,
    gap_array_size: u32,
    crc: u32,
};

pub fn decryptHeaderData(encrypted: [108]u8) HeaderData {
    var res: [108]u8 = undefined;

    var i: usize = 0;
    while (i < 108) : (i += 1) {
        res[i] = encrypted[i] ^ decryptionTable[i];
    }

    return @bitCast(HeaderData, res);
}
