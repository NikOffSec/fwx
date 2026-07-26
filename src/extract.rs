use anyhow::{Result, bail};
use binwalk::{
    Binwalk, extractors::common::get_extracted_files, signatures::common::SignatureResult,
};
use std::fs;
use std::path::Path;

const EXTRACT_DIR: &str = "./extracted";

const MAX_DEPTH: usize = 8;
const MAX_NODES: usize = 2000;

#[derive(Clone)]
pub enum ByteSource {
    Firmware,
    File(String),
}

/// A node is either a file binwalk carved out (`is_file`, whole-file bytes) or
/// a signature it detected inside some container (a byte range within `source`)
pub struct FileNode {
    /// Signature name or carved-file name shown to the user
    pub label: String,
    /// Offset of the bytes within `source`.
    pub offset: usize,
    /// Size of the bytes in `source` (0 = unknown / to end of container).
    pub size: usize,
    /// The container the bytes live in.
    pub source: ByteSource,
    /// Things found nested inside this node.
    pub children: Vec<FileNode>,
}

pub fn scan(firmware: &[u8]) -> Option<Vec<SignatureResult>> {
    let binwalker = Binwalk::new();
    let findings = binwalker.scan(firmware);
    if findings.is_empty() {
        return None;
    }
    Some(findings)
}

pub fn extract_recursive(filepath: String) -> Result<Vec<FileNode>> {
    if Path::new(EXTRACT_DIR).exists() {
        bail!(
            "output directory `{EXTRACT_DIR}` already exists; \
             move or remove it before extracting again"
        );
    }

    let binwalker = Binwalk::configure(
        Some(filepath),
        Some(EXTRACT_DIR.to_string()),
        None,
        None,
        None,
        false,
    )
    .map_err(|e| anyhow::anyhow!("failed to configure binwalk: {e:?}"))?;

    let mut node_count = 0;
    let nodes = analyze_into_nodes(
        &binwalker,
        &binwalker.base_target_file,
        &ByteSource::Firmware,
        0,
        &mut node_count,
    );

    Ok(nodes)
}

/// Analyze one file and turn its findings into tree nodes. Each detected
/// signature becomes a node (its bytes live in `source` at the reported
/// offset); if binwalk managed to carve files out of that signature, those
/// files become child nodes and are analyzed in turn.
fn analyze_into_nodes(
    binwalker: &Binwalk,
    target: &str,
    source: &ByteSource,
    depth: usize,
    node_count: &mut usize,
) -> Vec<FileNode> {
    if depth > MAX_DEPTH || *node_count >= MAX_NODES {
        return Vec::new();
    }

    // Scan and extract this one file (a single level; recursion is ours).
    let results = binwalker.analyze(&target.to_string(), true);

    let mut nodes = Vec::new();

    // `file_map` is already sorted by offset. Each entry is one thing binwalk
    // found inside `target`.
    for signature in &results.file_map {
        if *node_count >= MAX_NODES {
            break;
        }
        *node_count += 1;

        let mut node = FileNode {
            label: signature.name.clone(),
            offset: signature.offset,
            size: signature.size,
            source: source.clone(),
            children: Vec::new(),
        };

        // If this signature was successfully extracted into one or more files,
        // hang those files off it and dig into each.
        if let Some(extraction) = results.extractions.get(&signature.id)
            && extraction.success
        {
            for file_path in get_extracted_files(&extraction.output_directory) {
                if *node_count >= MAX_NODES {
                    break;
                }
                *node_count += 1;

                let size = fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0) as usize;
                let display = file_path
                    .rsplit('/')
                    .next()
                    .unwrap_or(&file_path)
                    .to_string();
                let child_source = ByteSource::File(file_path.clone());

                // Recurse into the carved file unless its extractor opted out.
                let children = if extraction.do_not_recurse {
                    Vec::new()
                } else {
                    analyze_into_nodes(binwalker, &file_path, &child_source, depth + 1, node_count)
                };

                node.children.push(FileNode {
                    label: display,
                    offset: 0,
                    size,
                    source: child_source,
                    children,
                });
            }
        }

        nodes.push(node);
    }

    nodes
}

pub fn extracted_file_paths(tree: &[FileNode]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut paths = Vec::new();
    collect_file_paths(tree, &mut seen, &mut paths);
    paths
}

fn collect_file_paths(
    nodes: &[FileNode],
    seen: &mut std::collections::HashSet<String>,
    paths: &mut Vec<String>,
) {
    for node in nodes {
        if let ByteSource::File(path) = &node.source
            && seen.insert(path.clone())
        {
            paths.push(path.clone());
        }
        collect_file_paths(&node.children, seen, paths);
    }
}

// THE TESTS (thanks claude)

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Wrap `data` in a gzip stream using the system gzip utility.
    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut child = Command::new("gzip")
            .arg("-c")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn gzip");
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(data)
            .expect("write to gzip");
        let out = child.wait_with_output().expect("gzip output");
        assert!(out.status.success());
        out.stdout
    }

    /// Depth-first count of every node in a tree.
    fn count(nodes: &[FileNode]) -> usize {
        nodes.iter().map(|n| 1 + count(&n.children)).sum()
    }

    /// Prints the recovered tree for the checked-in firmware. Ignored by
    /// default (slow, depends on the sample file); run with
    /// `cargo test dump_real_firmware -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_real_firmware() {
        let fw = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/openwrt-25.12.5-ath79-generic-adtran_bsap1840-squashfs-kernel.bin"
        );
        let workdir = std::env::temp_dir().join("fwx_real_dump");
        let _ = fs::remove_dir_all(&workdir);
        fs::create_dir_all(&workdir).unwrap();
        std::env::set_current_dir(&workdir).unwrap();

        let tree = extract_recursive(fw.to_string()).expect("extraction");
        fn show(nodes: &[FileNode], depth: usize) {
            for n in nodes {
                eprintln!(
                    "{}0x{:08x} {:<12} {} bytes",
                    "  ".repeat(depth),
                    n.offset,
                    n.label,
                    n.size
                );
                show(&n.children, depth + 1);
            }
        }
        show(&tree, 0);

        std::env::set_current_dir(std::env::temp_dir()).unwrap();
        let _ = fs::remove_dir_all(&workdir);
    }

    /// A gzip-inside-a-gzip must be peeled twice: a single-level extract only
    /// sees the outer gzip, while the recursive walk should reach the buried
    /// payload nested two carved files deep.
    #[test]
    fn recursion_peels_nested_gzip() {
        let payload = b"BURIED_FIRMWARE_PAYLOAD_0123456789";
        let nested = gzip(&gzip(payload));

        // Work in an isolated temp dir so EXTRACT_DIR ("./extracted") stays local.
        let workdir = std::env::temp_dir().join(format!("fwx_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&workdir);
        fs::create_dir_all(&workdir).unwrap();
        std::env::set_current_dir(&workdir).unwrap();

        let fw_path = "nested.gz";
        fs::write(fw_path, &nested).unwrap();

        let tree = extract_recursive(fw_path.to_string()).expect("extraction");

        // Expect a chain: outer gzip -> carved file -> inner gzip -> carved
        // file, i.e. a tree at least a few levels deep.
        fn max_depth(nodes: &[FileNode]) -> usize {
            nodes
                .iter()
                .map(|n| 1 + max_depth(&n.children))
                .max()
                .unwrap_or(0)
        }
        assert!(
            max_depth(&tree) >= 3,
            "expected the nested gzip to peel a few levels deep, tree had {} nodes / depth {}",
            count(&tree),
            max_depth(&tree),
        );

        std::env::set_current_dir(std::env::temp_dir()).unwrap();
        let _ = fs::remove_dir_all(&workdir);
    }
}
