use glob::Pattern;
use pnet::datalink;
use pnet::datalink::NetworkInterface;
use std::collections::HashSet;

pub struct InterfaceHandler {
    patterns: Vec<String>,
}

impl InterfaceHandler {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    pub fn get_interfaces(&self) -> Vec<NetworkInterface> {
        let interfaces = datalink::interfaces();
        let explicit: HashSet<String> = self
            .patterns
            .iter()
            .filter(|p| !p.contains('*') && !p.contains('?'))
            .cloned()
            .collect();

        interfaces
            .into_iter()
            .filter(|iface| self.matches_patterns(&iface.name))
            .filter(|iface| Self::should_capture_interface(&iface.name, &explicit))
            .collect()
    }

    fn matches_patterns(&self, iface_name: &str) -> bool {
        self.patterns.iter().any(|pattern| {
            if pattern == "*" {
                return true;
            }
            Pattern::new(pattern)
                .map(|compiled| compiled.matches(iface_name))
                .unwrap_or(false)
        })
    }

    pub fn should_capture_interface(name: &str, explicit_interfaces: &HashSet<String>) -> bool {
        if !name.contains('.') {
            return true;
        }

        explicit_interfaces.contains(name)
    }
}

#[cfg(test)]
mod tests {
    use super::InterfaceHandler;
    use std::collections::HashSet;

    #[test]
    fn vlan_sub_interface_is_ignored_without_explicit_config() {
        let explicit = HashSet::new();
        assert!(!InterfaceHandler::should_capture_interface(
            "eth0.100", &explicit
        ));
        assert!(InterfaceHandler::should_capture_interface(
            "eth0", &explicit
        ));
    }

    #[test]
    fn vlan_sub_interface_can_be_enabled_explicitly() {
        let mut explicit = HashSet::new();
        explicit.insert("eth0.100".to_string());
        assert!(InterfaceHandler::should_capture_interface(
            "eth0.100", &explicit
        ));
    }
}
