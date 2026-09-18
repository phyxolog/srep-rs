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
        n = n
            .checked_mul(10)
            .and_then(|v| v.checked_add((bytes[i] - b'0') as u64))
            .ok_or("bad number")?;
        i += 1;
    }
    let c = if i < bytes.len() { bytes[i] as char } else { spec };
    match c {
        'b' => Ok(n),
        'k' => Ok(n.checked_mul(1024).ok_or("size too large")?),
        'm' => Ok(n
            .checked_mul(1024)
            .and_then(|v| v.checked_mul(1024))
            .ok_or("size too large")?),
        'g' => Ok(n
            .checked_mul(1024)
            .and_then(|v| v.checked_mul(1024))
            .and_then(|v| v.checked_mul(1024))
            .ok_or("size too large")?),
        '^' => {
            if n >= 64 {
                return Err("size too large".into());
            }
            Ok(1u64 << n)
        }
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
    let total = (percent as i128) * ((physical_mem() / 100) as i128) - (sub as i128);
    Ok(total.clamp(0, i128::from(u64::MAX)) as u64)
}

fn physical_mem() -> u64 {
    if let Ok(out) = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        && let Some(v) = String::from_utf8(out.stdout)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    {
        return v;
    }
    8 * 1024 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::parse_mem;

    #[test]
    fn parse_mem_digit_overflow() {
        assert!(parse_mem("99999999999999999999", 'b').is_err());
    }

    #[test]
    fn parse_mem_suffixes() {
        assert_eq!(parse_mem("1g", 'b').unwrap(), 1073741824);
        assert_eq!(parse_mem("63", '^').unwrap(), 1u64 << 63);
    }

    #[test]
    fn parse_mem_shift_out_of_range() {
        assert!(parse_mem("64", '^').is_err());
    }

    #[test]
    fn parse_mem_megabytes_overflow() {
        // 2^44 * 2^20 == 2^64 overflows the u64 'm' multiplier.
        assert!(parse_mem("17592186044416", 'm').is_err());
    }
}