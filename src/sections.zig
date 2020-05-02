pub const SystemSection = struct {
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

pub const PageInfo = struct {
    number: i32,
    size: u32,
    address: u32,
};
// class dwgPageInfo {
    // public:
    //     dwgPageInfo(){}
    //     dwgPageInfo(duint64 i, duint64 ad, duint32 sz){
    //         Id=i; address=ad; size=sz;
    //     }
    //     ~dwgPageInfo(){}
    //     duint64 Id;
    //     duint64 address; //in file stream, for rd18, rd21
    //     duint64 size; //in file stream, for rd18, rd21
    //     duint64 dataSize; //for rd18, rd21
    //     duint32 startOffset; //for rd18, rd21
    //     duint64 cSize; //compresed page size, for rd21
    //     duint64 uSize; //uncompresed page size, for rd21
    // };
