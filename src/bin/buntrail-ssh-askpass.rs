#[cfg(unix)]
fn main() {
    if buntrail_services::connections::authentication::askpass().is_err() {
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("SSH authentication helper is unavailable on this platform");
    std::process::exit(1);
}
