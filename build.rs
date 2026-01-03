fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);

    if !ida_path.exists() || !idalib_path.exists() {
        println!("cargo::warning=IDA installation not found, using SDK stubs");
        idalib_build::configure_idasdk_linkage();
    } else {
        // Sets RPATH to IDA installation so libraries are found at runtime
        idalib_build::configure_linkage()?;
    }

    Ok(())
}
