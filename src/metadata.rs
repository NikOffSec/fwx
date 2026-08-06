use rust_strings::{BytesConfig, strings};

pub const IMPORTANT_KEYWORDS: &[&str] = &[
    // versioning / build info
    "version",
    "release",
    "revision",
    "firmware",
    "kernel",
    "linux",
    "u-boot",
    "uboot",
    "busybox",
    "openwrt",
    "gcc",
    "compiled",
    "build",
    // credentials / auth
    "password",
    "passwd",
    "shadow",
    "root:",
    "admin",
    "login",
    "username",
    "secret",
    "credential",
    "token",
    "api_key",
    "apikey",
    "private key",
    // crypto / keys / certs
    "-----begin",
    "ssh-rsa",
    "ssh-dss",
    "certificate",
    "pgp",
    // boot / config
    "bootargs",
    "bootcmd",
    "nvram",
    "/etc/",
    "mtdparts",
    "squashfs",
    // network
    "http://",
    "https://",
    "ftp://",
    "telnet",
    "dropbear",
    "ssid",
    "wpa",
];

pub fn is_important(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    IMPORTANT_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

pub fn prioritize_strings(found: Vec<(String, u64)>) -> Vec<(String, u64, bool)> {
    let mut tagged: Vec<(String, u64, bool)> = found
        .into_iter()
        .map(|(s, off)| {
            let important = is_important(&s);
            (s, off, important)
        })
        .collect();
    tagged.sort_by(|a, b| b.2.cmp(&a.2));
    tagged
}

pub fn extract_strings(firmware: &[u8]) -> Result<Vec<(String, u64)>, Box<dyn std::error::Error>> {
    let config = BytesConfig::new(firmware.to_vec()).with_min_length(4);
    Ok(strings(&config)?)
}

/// Shannon entropy (0.0–8.0 bits) of one block.
fn shannon_entropy(block: &[u8]) -> f64 {
    if block.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in block {
        counts[b as usize] += 1;
    }
    let len = block.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// (offset, entropy) per block.
pub fn entropy_scan(firmware: &[u8], block_size: usize) -> Vec<(usize, f64)> {
    firmware
        .chunks(block_size)
        .enumerate()
        .map(|(i, chunk)| (i * block_size, shannon_entropy(chunk)))
        .collect()
}
