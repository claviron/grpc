fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptors_path = out_dir.join("descriptors.bin");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(&descriptors_path)
        .compile_protos(
            &[
                "proto/greeter.proto",
                "proto/acme.proto",
                "proto/mtls.proto",
                "proto/certificates.proto",
                "proto/aliases.proto",
                "proto/dns.proto",
                "proto/domains.proto",
                "proto/applications.proto",
                "proto/linked.proto",
                "proto/server.proto",
                "proto/services.proto",
                "proto/tasks.proto",
                "proto/workers.proto",
                "proto/management.proto",
                "proto/users.proto",
            ],
            &["proto"],
        )?;

    println!("cargo:rerun-if-changed=proto/greeter.proto");
    println!("cargo:rerun-if-changed=proto/acme.proto");
    println!("cargo:rerun-if-changed=proto/mtls.proto");
    println!("cargo:rerun-if-changed=proto/certificates.proto");
    println!("cargo:rerun-if-changed=proto/aliases.proto");
    println!("cargo:rerun-if-changed=proto/dns.proto");
    println!("cargo:rerun-if-changed=proto/domains.proto");
    println!("cargo:rerun-if-changed=proto/applications.proto");
    println!("cargo:rerun-if-changed=proto/linked.proto");
    println!("cargo:rerun-if-changed=proto/server.proto");
    println!("cargo:rerun-if-changed=proto/services.proto");
    println!("cargo:rerun-if-changed=proto/tasks.proto");
    println!("cargo:rerun-if-changed=proto/workers.proto");
    println!("cargo:rerun-if-changed=proto/management.proto");
    println!("cargo:rerun-if-changed=proto/users.proto");

    Ok(())
}
