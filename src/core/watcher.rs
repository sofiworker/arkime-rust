use std::io;

#[cfg(target_os = "windows")]
fn get_interfaces() -> io::Result<()> {}

#[cfg(target_os = "linux")]
fn get_interfaces() -> io::Result<String> {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    Ok(buffer)
}
