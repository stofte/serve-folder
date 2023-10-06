// build.rs

fn main() {
    cc::Build::new()
        .file("src/win32.c")
        .compile("win32");
    println!("cargo:rerun-if-changed=src/win32.c");
}
