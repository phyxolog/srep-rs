use std::fs::{File, OpenOptions};
use std::io::{Write};
use std::process::ExitCode;

use srep_rs::checksum::hash_by_name;
use srep_rs::compress::{CompressOptions, Layout};
use srep_rs::decode::DecompressOptions;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args[1..]) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            eprintln!("\n  ERROR! {msg}");
            ExitCode::from(code)
        }
    }
}

struct Cli {
    decompress: bool,
    method: i8,
    layout: Layout,
    hash_name: String,
    l: u64,
    min_match: u64,
    bufsize: u64,
    mem: u64,
    vm_block: u64,
    vmfile: String,
    maximum_save: u32,
    checksum_seed: Option<Vec<u8>>,
    filenames: Vec<String>,
}

const MB: u64 = 1024 * 1024;

fn run(args: &[String]) -> Result<(), (u8, String)> {
    let mut cli = Cli {
        decompress: false,
        method: 3i8,
        layout: Layout::IndexLz,
        hash_name: "vmac".into(),
        l: 0,
        min_match: 0,
        bufsize: 8 * MB,
        mem: 0,
        vm_block: 8 * MB,
        vmfile: "srep-virtual-memory.tmp".into(),
        maximum_save: u32::MAX,
        checksum_seed: None,
        filenames: Vec::new(),
    };

    for a in args {
        if a == "-d" {
            cli.decompress = true;
        } else if a == "-f" {
            cli.layout = Layout::FutureLz;
        } else if let Some(rest) = a.strip_prefix("-m") {
            let d = rest.as_bytes();
            let is_method = if d.len() >= 1 && (d[0].is_ascii_digit() || d[0] == b'x') {
                if d.len() == 1 {
                    true
                } else if d.len() == 2 && (d[1] == b'f' || d[1] == b'o') {
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if is_method {
                let m = if d[0] == b'x' { 5 } else { (d[0] - b'0') as i8 };
                cli.method = m;
                cli.layout = if d.len() == 2 && d[1] == b'f' {
                    Layout::FutureLz
                } else if d.len() == 2 && d[1] == b'o' {
                    Layout::IoLz
                } else {
                    Layout::IndexLz
                };
            } else if let Ok(m) = srep_rs::cli::parse_mem(rest, 'b') {
                cli.maximum_save = m as u32;
            }
        } else if a == "-hash-" || a == "-nomd5" {
            cli.hash_name = String::new();
        } else if let Some(v) = a.strip_prefix("-hash=") {
            cli.hash_name = v.to_string();
        } else if let Some(v) = a.strip_prefix("--checksum-seed=") {
            cli.checksum_seed = Some(hex::decode(v).map_err(|_| (2, "bad seed hex".into()))?);
        } else if let Some(v) = a.strip_prefix("-l") {
            cli.min_match = srep_rs::cli::parse_mem(v, 'b').map_err(|e| (2, e))?;
        } else if let Some(v) = a.strip_prefix("-c") {
            cli.l = srep_rs::cli::parse_mem(v, 'b').map_err(|e| (2, e))?;
        } else if let Some(v) = a.strip_prefix("-b") {
            cli.bufsize = srep_rs::cli::parse_mem(v, 'm').map_err(|e| (2, e))?;
        } else if let Some(v) = a.strip_prefix("-mem") {
            cli.mem = srep_rs::cli::parse_mem_option(v, 'm').map_err(|e| (2, e))?;
        } else if let Some(v) = a.strip_prefix("-vmblock=") {
            cli.vm_block = srep_rs::cli::parse_mem(v, 'm').map_err(|e| (2, e))?;
        } else if let Some(v) = a.strip_prefix("-vmfile=") {
            cli.vmfile = v.to_string();
        } else if a.starts_with('-') && a != "-" {
            // ignore unknown options for now
        } else {
            cli.filenames.push(a.clone());
        }
    }

    if cli.filenames.is_empty() {
        return Err((2, "usage: srep-rs [-d] [options] infile [outfile]".into()));
    }
    let fin_name = cli.filenames[0].clone();
    let fout_name = if cli.filenames.len() >= 2 {
        cli.filenames[1].clone()
    } else if cli.decompress {
        if fin_name.ends_with(".srep") {
            fin_name[..fin_name.len() - 5].to_string()
        } else {
            return Err((2, "cannot infer output name".into()));
        }
    } else {
        fin_name.clone() + ".srep"
    };

    if cli.decompress {
        let mut opts = DecompressOptions::default();
        opts.forced_checksum = if cli.hash_name.is_empty() {
            Some(srep_rs::checksum::BlockChecksum::None)
        } else {
            None
        };
        if cli.mem != 0 {
            opts.vm_mem = cli.mem;
        }
        opts.vm_block = cli.vm_block;
        opts.vmfile_name = cli.vmfile.clone();
        opts.bufsize = cli.bufsize;
        opts.maximum_save = cli.maximum_save;
        let mut fin = File::open(&fin_name).map_err(|e| (3, format!("Can't open {fin_name}: {e}")))?;
        let mut fout = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&fout_name)
            .map_err(|e| (3, format!("Can't open {fout_name}: {e}")))?;
        srep_rs::decode::decompress(&mut fin, &mut fout, &opts).map_err(|e| (4, e))?;
    } else {
        // Compression.
        let desc = hash_by_name(&cli.hash_name).ok_or((2, "unknown hash".to_string()))?;
        let input = std::fs::read(&fin_name).map_err(|e| (3, format!("Can't open {fin_name}: {e}")))?;
        let opts = CompressOptions {
            method: cli.method as i8,
            l: cli.l as u64,
            min_match: cli.min_match as u64,
            dict_min_match: 512,
            bufsize: cli.bufsize,
            layout: cli.layout,
            hash_num: desc.hash_num,
            checksum_seed: cli.checksum_seed,
            dictsize: 0,
            dict_hashsize: 0,
            dict_chunk: 0,
        };
        let out = srep_rs::compress::compress(&input, &opts).map_err(|e| (4, e))?;
        let mut f = File::create(&fout_name).map_err(|e| (3, format!("Can't open {fout_name}: {e}")))?;
        f.write_all(&out).map_err(|e| (3, e.to_string()))?;
    }
    Ok(())
}

// Tiny hex decoder for --checksum-seed.
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}