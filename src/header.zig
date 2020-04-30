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
    encrypted_data: [108]u8,
    magic_number_seq: [20]u8,
};

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

pub const DecryptedData = packed struct {
    file_id: [12]u8,
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

pub fn decryptHeaderEncryptedData(encrypted: [108]u8) DecryptedData {
    var res: [108]u8 = undefined;

    var i: usize = 0;
    while (i < 108) : (i += 1) {
        res[i] = encrypted[i] ^ decryptionTable[i];
    }

    return @bitCast(DecryptedData, res);
}
