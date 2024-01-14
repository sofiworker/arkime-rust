use serde_derive::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    name: String,
    age: u32,
    email: Option<String>,
}
