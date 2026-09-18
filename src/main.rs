use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Read, Write};
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
    dictsize: u64,
    dict_hashsize: u64,
    dict_chunk: u64,
    dict_min_match: u64,
    tempfile: Option<String>,
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
        dictsize: 0,
        dict_hashsize: 0,
        dict_chunk: 0,
        dict_min_match: 0,
        tempfile: None,
        filenames: Vec::new(),
    };

    for a in args {
        if a == "-d" {
            cli.decompress = true;
        } else if a == "-f" {
            cli.layout = Layout::FutureLz;
        } else if a == "-d-" {
            cli.dictsize = 0;
        } else if a == "-d+" {
            cli.dictsize = 512 * MB;
        } else if let Some(rest) = a.strip_prefix("-d") {
            // -d<size>[:options] colon-separated dictionary options.
            for part in rest.split(':') {
                if part.is_empty() {
                    continue;
                }
                let b = part.as_bytes();
                match b[0] {
                    b'd' => cli.dictsize = srep_rs::cli::parse_mem_option(&part[1..], 'm').map_err(|e| (2, e))?,
                b'h' => cli.dict_hashsize = srep_rs::cli::parse_mem_option(&part[1..], 'm').map_err(|e| (2, e))?,
                b'l' => cli.dict_min_match = srep_rs::cli::parse_mem(&part[1..], 'b').map_err(|e| (2, e))?,
                b'c' => cli.dict_chunk = srep_rs::cli::parse_mem(&part[1..], 'b').map_err(|e| (2, e))?,
                b'a' => {} // ignore -da
                _ => cli.dictsize = srep_rs::cli::parse_mem_option(part, 'm').map_err(|e| (2, e))?,
                }
            }
        } else if let Some(rest) = a.strip_prefix("-m") {
            let d = rest.as_bytes();
            let is_method = !d.is_empty()
                && (d[0].is_ascii_digit() || d[0] == b'x')
                && (d.len() == 1 || (d.len() == 2 && (d[1] == b'f' || d[1] == b'o')));
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
            } else {
                let m = srep_rs::cli::parse_mem(rest, 'b').map_err(|e| (2, e))?;
                cli.maximum_save = u32::try_from(m).map_err(|_| (2, "size too large".into()))?;
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
        } else if a == "-temp=" {
            cli.tempfile = Some(String::new());
        } else if let Some(v) = a.strip_prefix("-temp=") {
            cli.tempfile = Some(v.to_string());
        } else if a.starts_with('-') && a != "-" {
            return Err((2, format!("Invalid option: {a}")));
        } else {
            cli.filenames.push(a.clone());
        }
    }

    if cli.filenames.is_empty()
        && !std::io::stdin().is_terminal()
        && !std::io::stdout().is_terminal()
    {
        cli.filenames = vec!["-".to_string(), "-".to_string()];
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
        let mut opts = DecompressOptions {
            forced_checksum: if cli.hash_name.is_empty() {
                Some(srep_rs::checksum::BlockChecksum::None)
            } else {
                None
            },
            vm_block: cli.vm_block,
            vmfile_name: cli.vmfile.clone(),
            bufsize: cli.bufsize,
            maximum_save: cli.maximum_save,
            tempfile_name: cli.tempfile.clone(),
            ..DecompressOptions::default()
        };
        if cli.mem != 0 {
            opts.vm_mem = cli.mem;
        }

        // Spool file: a seekable copy of a stdin archive, and/or the seekable
        // output backend when writing to stdout (the decoder rereads prior output).
        let spool = match &cli.tempfile {
            Some(s) if s.is_empty() => None, // -temp= : explicitly disabled
            Some(s) => Some(s.clone()),
            None => Some("srep-data.tmp".to_string()),
        };
        let fin_is_stdin = fin_name == "-";
        let fout_is_stdout = fout_name == "-";
        if spool.is_none() && (fin_is_stdin || fout_is_stdout) {
            return Err((3, "without tempfile isn't supported".into()));
        }

        // Open a seekable input: a stdin archive is spooled to disk (the decoder
        // seeks for v4 index/footer), a regular file is opened read/write.
        let (mut fin, input_spool): (File, Option<String>) = if fin_is_stdin {
            let path = spool.clone().unwrap();
            let mut write_handle = File::create(&path)
                .map_err(|e| (3, format!("Can't create {path}: {e}")))?;
            std::io::copy(&mut std::io::stdin(), &mut write_handle)
                .map_err(|e| (3, e.to_string()))?;
            drop(write_handle);
            let fh = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|e| (3, format!("Can't open {path}: {e}")))?;
            (fh, Some(path))
        } else {
            (
                File::open(&fin_name).map_err(|e| (3, format!("Can't open {fin_name}: {e}")))?,
                None,
            )
        };

        if fout_is_stdout {
            // Output backend is a temp file; mirror each block to stdout.
            let out_spool = if fin_is_stdin {
                format!("{}.out", spool.as_deref().unwrap())
            } else {
                spool.clone().unwrap()
            };
            let mut temp = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&out_spool)
                .map_err(|e| (3, format!("Can't open {out_spool}: {e}")))?;
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            let result = srep_rs::decode::decompress(&mut fin, &mut temp, Some(&mut lock), &opts);
            drop(lock);
            let _ = std::fs::remove_file(&out_spool);
            if let Some(p) = &input_spool {
                let _ = std::fs::remove_file(p);
            }
            result.map_err(|e| (4, e))?;
        } else {
            let mut fout = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&fout_name)
                .map_err(|e| (3, format!("Can't open {fout_name}: {e}")))?;
            let result =
                srep_rs::decode::decompress(&mut fin, &mut fout, None::<&mut std::io::Stdout>, &opts);
            if let Some(p) = &input_spool {
                let _ = std::fs::remove_file(p);
            }
            if result.is_err() && fout_name != "-" {
                let _ = std::fs::remove_file(&fout_name);
            }
            result.map_err(|e| (4, e))?;
        }
    } else {
        // Compression holds the whole input in RAM, so stdin needs no spool file.
        let desc = hash_by_name(&cli.hash_name).ok_or((2, "unknown hash".to_string()))?;
        let input = if fin_name == "-" {
            let mut v = Vec::new();
            std::io::stdin().read_to_end(&mut v).map_err(|e| (3, e.to_string()))?;
            v
        } else {
            std::fs::read(&fin_name).map_err(|e| (3, format!("Can't open {fin_name}: {e}")))?
        };
        let opts = CompressOptions {
            method: cli.method,
            l: cli.l,
            min_match: cli.min_match,
            dict_min_match: if cli.dict_min_match != 0 { cli.dict_min_match } else { 512 },
            bufsize: cli.bufsize,
            layout: cli.layout,
            hash_num: desc.hash_num,
            checksum_seed: cli.checksum_seed,
            dictsize: cli.dictsize,
            dict_hashsize: cli.dict_hashsize,
            dict_chunk: cli.dict_chunk,
        };
        let out = srep_rs::compress::compress(&input, &opts).map_err(|e| (4, e))?;
        if fout_name == "-" {
            std::io::stdout().write_all(&out).map_err(|e| (3, e.to_string()))?;
        } else {
            let mut f = File::create(&fout_name).map_err(|e| (3, format!("Can't open {fout_name}: {e}")))?;
            if let Err(e) = f.write_all(&out) {
                let _ = std::fs::remove_file(&fout_name);
                return Err((3, e.to_string()));
            }
        }
    }
    Ok(())
}

// Tiny hex decoder for --checksum-seed.
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if !s.len().is_multiple_of(2) {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}