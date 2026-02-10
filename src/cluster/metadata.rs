use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LwwValue {
    pub ts_millis: u64,
    pub node_id: String,
    pub value: Value,
}

#[derive(Debug, Default)]
pub struct LwwMap {
    // key -> last-write-wins value
    map: HashMap<String, LwwValue>,
}

impl LwwMap {
    pub fn set(&mut self, key: String, value: LwwValue) {
        match self.map.get(&key) {
            Some(existing) => {
                if is_newer(&value, existing) {
                    self.map.insert(key, value);
                }
            }
            None => {
                self.map.insert(key, value);
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&LwwValue> {
        self.map.get(key)
    }

    pub fn snapshot(&self) -> HashMap<String, LwwValue> {
        self.map.clone()
    }

    pub fn merge(&mut self, other: HashMap<String, LwwValue>) {
        for (k, v) in other {
            self.set(k, v);
        }
    }
}

fn is_newer(a: &LwwValue, b: &LwwValue) -> bool {
    if a.ts_millis != b.ts_millis {
        return a.ts_millis > b.ts_millis;
    }
    // Deterministic tie-breaker.
    a.node_id > b.node_id
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

