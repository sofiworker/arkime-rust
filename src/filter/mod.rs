use crate::layer::ParsedPacket;

#[derive(Default)]
pub struct PacketFilter;

impl PacketFilter {
    pub fn allow(&self, _packet: &ParsedPacket) -> bool {
        true
    }
}
