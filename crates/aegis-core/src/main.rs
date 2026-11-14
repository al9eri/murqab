use aegis_core::{sanitize_bytes, scan_bytes, ScanReport};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

fn collect_targets(target: &Path, out: &mut Vec<PathBuf>) {
    if target.is_file() {
        out.push(target.to_path_buf());
        return;
    }
    if let Ok(entries) = fs::read_dir(target) {
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == ".git" || name == "__pycache__" || name == "target" {
                continue;
            }
            if p.is_dir() {
                collect_targets(&p, out);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
}

fn print_human(reports: &[ScanReport]) {
    for r in reports {
        let badge = match r.verdict.as_str() {
            "CLEAN" => "[OK]",
            "FLAGGED" => "[WARN]",
            _ => "[BLOCK]",
        };
        println!(
            "{badge} {}  (risk={:.2}, sha256={}...)",
            r.source,
            r.risk_score,
            &r.sha256[..12.min(r.sha256.len())]
        );
        for f in &r.findings {
            println!(
                "    -> {} [{}] line {}: {} ({})",
                f.rule_id,
                f.severity.as_str(),
                f.line,
                f.description,
                f.snippet
            );
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage: aegis <scan|sanitize> <path> [--json] [--strict] [-o <out>]");
        process::exit(1);
    }

    match args[0].as_str() {
        "sanitize" => {
            let Some(path_str) = args.get(1) else {
                eprintln!("Missing target file path");
                process::exit(1);
            };
            let Ok(bytes) = fs::read(path_str) else {
                eprintln!("Failed to read file: {path_str}");
                process::exit(1);
            };
            let cleaned = sanitize_bytes(&bytes);
            if let Some(pos) = args.iter().position(|a| a == "-o" || a == "--output") {
                if let Some(out_path) = args.get(pos + 1) {
                    if let Err(e) = fs::write(out_path, cleaned) {
                        eprintln!("Failed to write output: {e}");
                        process::exit(1);
                    }
                    return;
                }
            }
            println!("{cleaned}");
        }
        "scan" => {
            let Some(path_str) = args.get(1) else {
                eprintln!("Missing target path");
                process::exit(1);
            };
            let json_out = args.iter().any(|a| a == "--json");
            let strict = args.iter().any(|a| a == "--strict");

            let mut targets = Vec::new();
            collect_targets(Path::new(path_str), &mut targets);
            let reports: Vec<ScanReport> = targets
                .iter()
                .filter_map(|p| {
                    fs::read(p)
                        .ok()
                        .map(|b| scan_bytes(&b, &p.to_string_lossy()))
                })
                .collect();

            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&reports).unwrap_or_else(|_| "[]".into())
                );
            } else {
                print_human(&reports);
            }

            if reports.iter().any(|r| r.verdict == "QUARANTINE") {
                process::exit(2);
            }
            if strict && reports.iter().any(|r| r.verdict != "CLEAN") {
                process::exit(1);
            }
        }
        other => {
            eprintln!("Unknown command: {other}");
            process::exit(1);
        }
    }
}
