// Command-line parsing helpers (parseMem / parseMem64 semantics).

/// Parse a memory size like `512`, `8mb`, `4k`, `1g`, `^20` (2^20).
/// `spec` is a default suffix when none is present (like the C `parseMem`).
pub fn parse_mem(param: &str, spec: char) -> Result<u64, String> {
    let s = if let Some(rest) = param.strip_prefix('=') {
        rest
    } else {
        param
    };
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return Err("bad number".to_string());
    }
    let mut i = 0;
    let mut n: u64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        n = n * 10 + (bytes[i] - b'0') as u64;
        i += 1;
    }
    let c = if i < bytes.len() { bytes[i] as char } else { spec };
    match c {
        'b' => Ok(n),
        'k' => Ok(n * 1024),
        'm' => Ok(n * 1024 * 1024),
        'g' => Ok(n * 1024 * 1024 * 1024),
        '^' => Ok(1u64 << n),
        _ => Err("bad size suffix".to_string()),
    }
}

/// Parse `-mem75%` / `-mem75%-600mb` style options.
pub fn parse_mem_option(option: &str, spec: char) -> Result<u64, String> {
    if let Ok(m) = parse_mem(option, spec) {
        return Ok(m);
    }
    let bytes = option.as_bytes();
    let mut i = 0usize;
    let mut percent: u64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        percent = percent * 10 + (bytes[i] - b'0') as u64;
        i += 1;
    }
    if i >= bytes.len() || (bytes[i] != b'%' && bytes[i] != b'p') {
        return Err("bad mem option".to_string());
    }
    i += 1;
    let sub = if i < bytes.len() {
        if bytes[i] != b'-' {
            return Err("bad mem option".to_string());
        }
        parse_mem(&option[i + 1..], 'm')?
    } else {
        0
    };
    Ok(percent * (physical_mem() / 100) - sub)
}

fn physical_mem() -> u64 {
    if let Ok(out) = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
    {
        if let Some(v) = String::from_utf8(out.stdout)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            return v;
        }
    }
    8 * 1024 * 1024 * 1024
}