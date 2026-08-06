use capstone::prelude::*;
use object::{Architecture, Endianness, Object, ObjectSection};

/// One disassembled instruction: (address, hex bytes, mnemonic, operands).
pub type Insn = (u64, String, String, String);

/// Metadata the user supplies by hand when automatic detection fails.
pub struct ManualMeta {
    pub arch: Architecture,
    pub endian: Endianness,
    pub base_addr: u64,
    /// Byte offset into the firmware where code begins.
    pub offset: usize,
}

pub fn parse_arch(s: &str) -> Option<Architecture> {
    match s.trim().to_ascii_lowercase().as_str() {
        "x86_64" | "x64" | "amd64" => Some(Architecture::X86_64),
        "i386" | "x86" | "x86_32" | "i686" => Some(Architecture::I386),
        "aarch64" | "arm64" => Some(Architecture::Aarch64),
        "arm" | "armv7" | "armel" | "armeb" => Some(Architecture::Arm),
        "mips" => Some(Architecture::Mips),
        "mips64" => Some(Architecture::Mips64),
        "ppc64" | "powerpc64" => Some(Architecture::PowerPc64),
        "riscv64" | "rv64" => Some(Architecture::Riscv64),
        "riscv32" | "rv32" => Some(Architecture::Riscv32),
        _ => None,
    }
}

pub fn parse_endian(s: &str) -> Option<Endianness> {
    match s.trim().to_ascii_lowercase().as_str() {
        "little" | "le" | "l" => Some(Endianness::Little),
        "big" | "be" | "b" => Some(Endianness::Big),
        _ => None,
    }
}

pub fn parse_hex(s: &str) -> Option<u64> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.is_empty() {
        return None;
    }
    u64::from_str_radix(t, 16).ok()
}

fn text_section(firmware: &[u8]) -> Option<(Vec<u8>, u64)> {
    let file = object::File::parse(firmware).ok()?;
    let text = file.section_by_name(".text")?;
    let bytes = text.data().ok()?.to_vec();
    let addr = text.address();
    Some((bytes, addr))
}

fn detect_arch(firmware: &[u8]) -> Option<(Architecture, Endianness)> {
    let file = object::File::parse(firmware).ok()?;
    Some((file.architecture(), file.endianness()))
}

fn build_capstone(archv: Architecture, endian: Endianness) -> Result<Capstone, &'static str> {
    let big = matches!(endian, Endianness::Big);

    let cs = match archv {
        Architecture::X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
        Architecture::I386 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .detail(true)
            .build(),

        Architecture::Aarch64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build(),
        Architecture::Arm => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .endian(if big {
                capstone::Endian::Big
            } else {
                capstone::Endian::Little
            })
            .detail(true)
            .build(),

        Architecture::Mips64 => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips64)
            .endian(if big {
                capstone::Endian::Big
            } else {
                capstone::Endian::Little
            })
            .detail(true)
            .build(),
        Architecture::Mips => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips32)
            .endian(if big {
                capstone::Endian::Big
            } else {
                capstone::Endian::Little
            })
            .detail(true)
            .build(),

        Architecture::PowerPc64 => Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode64)
            .detail(true)
            .build(),
        Architecture::Riscv64 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .detail(true)
            .build(),
        Architecture::Riscv32 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV32)
            .detail(true)
            .build(),

        _ => return Err("unsupported architecture"),
    };

    cs.map_err(|_| "failed to initialize capstone")
}

pub fn disassembler(firmware: &[u8]) -> Result<Vec<Insn>, String> {
    let (base_bytes, base_addr) = text_section(firmware)
        .ok_or("could not locate a .text section / base address (not a recognized object file)")?;

    let (archv, end) = detect_arch(firmware)
        .ok_or("architecture could not be identified from the file headers")?;

    disassemble_bytes(&base_bytes, base_addr, archv, end)
}

pub fn disassemble_manual(firmware: &[u8], meta: &ManualMeta) -> Result<Vec<Insn>, String> {
    let code = firmware
        .get(meta.offset..)
        .ok_or_else(|| format!("offset 0x{:x} is past the end of the file", meta.offset))?;

    if code.is_empty() {
        return Err("offset leaves no bytes to disassemble".to_string());
    }

    disassemble_bytes(code, meta.base_addr, meta.arch, meta.endian)
}

fn disassemble_bytes(
    code: &[u8],
    base_addr: u64,
    archv: Architecture,
    endian: Endianness,
) -> Result<Vec<Insn>, String> {
    let mut cs = build_capstone(archv, endian).map_err(|e| e.to_string())?;

    // continue disassembly past data sections (before it would just end)
    let _ = cs.set_skipdata(true);

    let insns = cs
        .disasm_all(code, base_addr)
        .map_err(|e| format!("capstone failed to disassemble: {e}"))?;

    if insns.is_empty() {
        return Err(
            "no instructions decoded — the arch, endianness, or offset is probably wrong"
                .to_string(),
        );
    }

    Ok(insns
        .iter()
        .map(|i| {
            let addr = i.address();
            let bytes = i
                .bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            let mnem = i.mnemonic().unwrap_or("").to_string();
            let ops = i.op_str().unwrap_or("").to_string();
            (addr, bytes, mnem, ops)
        })
        .collect())
}
