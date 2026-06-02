fn main() {
    println!("cargo::rustc-link-search=native=lib\\x64");
    println!("cargo::rustc-link-search=native=lib");
}
