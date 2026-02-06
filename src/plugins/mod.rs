use crate::layer::ParsedPacket;

pub trait PacketPlugin: Send {
    fn on_packet(&mut self, packet: &ParsedPacket);
}

#[derive(Default)]
pub struct PluginManager {
    plugins: Vec<Box<dyn PacketPlugin>>,
}

impl PluginManager {
    pub fn register(&mut self, plugin: Box<dyn PacketPlugin>) {
        self.plugins.push(plugin);
    }

    pub fn on_packet(&mut self, packet: &ParsedPacket) {
        for plugin in &mut self.plugins {
            plugin.on_packet(packet);
        }
    }
}
