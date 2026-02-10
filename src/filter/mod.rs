use std::io;
use tracing::warn;

#[derive(Clone, Default)]
pub struct PacketFilter {
    #[cfg(target_os = "linux")]
    inner: Option<std::sync::Arc<linux::PcapBpf>>,
    #[cfg(not(target_os = "linux"))]
    _configured: bool,
}

impl PacketFilter {
    pub fn from_config(bpf: &str, snaplen: u32) -> io::Result<Self> {
        let bpf = bpf.trim();
        if bpf.is_empty() {
            return Ok(Self::default());
        }

        #[cfg(target_os = "linux")]
        {
            let prog = linux::compile_filter(bpf, snaplen)?;
            return Ok(Self {
                inner: Some(std::sync::Arc::new(prog)),
            });
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = snaplen;
            warn!("net.bpf_filter is configured but BPF filtering is only implemented on Linux in this build; allowing all packets");
            Ok(Self { _configured: true })
        }
    }

    pub fn allow_frame(&self, frame: &[u8]) -> bool {
        #[cfg(target_os = "linux")]
        {
            let Some(inner) = &self.inner else {
                return true;
            };
            inner.matches(frame)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = frame;
            true
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use libc;
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::ptr;

    const DLT_EN10MB: i32 = 1;

    pub(super) struct PcapBpf {
        prog: pcap_sys::bpf_program,
    }

    // `bpf_program` is immutable after compilation; we only read from it in matches().
    // The underlying libpcap filter evaluator is re-entrant for independent calls.
    unsafe impl Send for PcapBpf {}
    unsafe impl Sync for PcapBpf {}

    impl Drop for PcapBpf {
        fn drop(&mut self) {
            unsafe {
                pcap_sys::pcap_freecode(&mut self.prog);
            }
        }
    }

    impl PcapBpf {
        pub(super) fn matches(&self, frame: &[u8]) -> bool {
            let hdr = pcap_sys::pcap_pkthdr {
                ts: pcap_sys::timeval { tv_sec: 0, tv_usec: 0 },
                caplen: frame.len() as u32,
                len: frame.len() as u32,
            };
            unsafe { pcap_sys::pcap_offline_filter(&self.prog, &hdr, frame.as_ptr()) != 0 }
        }
    }

    pub(super) fn compile_filter(expr: &str, snaplen: u32) -> io::Result<PcapBpf> {
        let expr = expr.trim();
        if expr.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "empty bpf filter"));
        }

        if let Some(rest) = expr.strip_prefix("ebpf:").or_else(|| expr.strip_prefix("cbpf:")) {
            return compile_ddd_program(rest);
        }

        let expr = expr
            .strip_prefix("tcpdump:")
            .or_else(|| expr.strip_prefix("pcap:"))
            .or_else(|| expr.strip_prefix("bpf:"))
            .unwrap_or(expr)
            .trim();

        let cexpr = CString::new(expr).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "bpf filter contains NUL byte",
            )
        })?;

        let mut prog = unsafe { MaybeUninit::<pcap_sys::bpf_program>::zeroed().assume_init() };
        let rc = unsafe {
            pcap_sys::pcap_compile_nopcap(
                snaplen as i32,
                DLT_EN10MB,
                &mut prog,
                cexpr.as_ptr(),
                1,
                0,
            )
        };

        if rc < 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("pcap_compile_nopcap failed for filter: {expr}"),
            ));
        }

        Ok(PcapBpf { prog })
    }

    fn compile_ddd_program(text: &str) -> io::Result<PcapBpf> {
        // Accept tcpdump -ddd output:
        //   <n>
        //   <code> <jt> <jf> <k>
        //   ...
        // Count line is optional; if present we validate.
        let mut lines = text
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect::<Vec<_>>();

        if lines.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "empty ebpf/cbpf program"));
        }

        let mut expected: Option<usize> = None;
        if lines.len() >= 2 && lines[0].split_whitespace().count() == 1 {
            if let Ok(n) = parse_u64(lines[0]) {
                expected = Some(n as usize);
                lines.remove(0);
            }
        }

        let mut insns = Vec::<pcap_sys::bpf_insn>::with_capacity(lines.len());
        for (idx, line) in lines.iter().enumerate() {
            let parts = line
                .split(|c: char| c.is_whitespace() || c == ',')
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>();
            if parts.len() != 4 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("invalid ebpf/cbpf instruction at line {}: {line}", idx + 1),
                ));
            }
            let code = parse_u64(parts[0])? as u16;
            let jt = parse_u64(parts[1])? as u8;
            let jf = parse_u64(parts[2])? as u8;
            let k = parse_u64(parts[3])? as u32;
            insns.push(pcap_sys::bpf_insn { code, jt, jf, k });
        }

        if let Some(n) = expected {
            if n != insns.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("ebpf/cbpf instruction count mismatch: header={n} actual={}", insns.len()),
                ));
            }
        }

        // Allocate with libc malloc so libpcap's free() can release it in pcap_freecode().
        let bytes = insns.len() * std::mem::size_of::<pcap_sys::bpf_insn>();
        let ptr = unsafe { libc::malloc(bytes) as *mut pcap_sys::bpf_insn };
        if ptr.is_null() {
            return Err(Error::new(ErrorKind::Other, "malloc failed for bpf_insn"));
        }
        unsafe {
            ptr::copy_nonoverlapping(insns.as_ptr(), ptr, insns.len());
        }

        let prog = pcap_sys::bpf_program {
            bf_len: insns.len() as u32,
            bf_insns: ptr,
        };

        Ok(PcapBpf { prog })
    }

    fn parse_u64(s: &str) -> io::Result<u64> {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).map_err(|_| {
                Error::new(ErrorKind::InvalidInput, format!("invalid hex integer: {s}"))
            })
        } else {
            s.parse::<u64>().map_err(|_| {
                Error::new(ErrorKind::InvalidInput, format!("invalid integer: {s}"))
            })
        }
    }
}
