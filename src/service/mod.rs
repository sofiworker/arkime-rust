#[derive(Debug, Clone, Copy)]
pub struct RuntimeStats {
    pub packets: u64,
    pub bytes: u64,
    pub sessions: usize,
}

impl RuntimeStats {
    pub fn to_json(self) -> String {
        format!(
            "{{\"packets\":{},\"bytes\":{},\"sessions\":{}}}",
            self.packets, self.bytes, self.sessions
        )
    }
}
