use std::{
    env::{self, current_dir},
    io,
    path::PathBuf,
    process::{Child, Command},
};

use std::process::ExitStatus;

use itertools::Itertools;

/// We need to create the initrd tar file with GNU tar. The tar library we're using to parse the tar file in the kernel
/// is not compatible with BSD tar.

#[cfg(target_os = "linux")]
fn make_tar(output: PathBuf) {
    let mut cmd = Command::new("tar");

    cmd.args(vec![
        "-C",
        "data",
        "--format=\"pax\"",
        "-cf",
        out.join("initrd.tar").to_str().unwrap(),
        "lat2-terminus16.psfu",
    ])
    .spawn()
    .expect("failed to build tar file");
}

#[cfg(target_os = "windows")]
fn make_tar(output: PathBuf) -> ExitStatus {
    let mut cmd = Command::new("wsl");

    let wsl_path = current_dir()
        .expect("failed to get current directory")
        .join("initrd")
        .canonicalize()
        .expect("failed to canonicalize current_directory path")
        .components()
        .map(|c| match c {
            std::path::Component::Prefix(_) => {
                // We just assume this is C:. Your build is probably broken if you're building on another drive or a
                // network share. Sorry. I just can't be assed to handle this kind of thing well. If you made it to this
                // point debugging a build issue, you're probably smart enough to fix it as well.
                "/mnt/c"
            }
            std::path::Component::RootDir => "",
            std::path::Component::CurDir => ".",
            std::path::Component::ParentDir => "..",
            std::path::Component::Normal(s) => s
                .to_str()
                .expect("failed to convert os path segment to str"),
        })
        .join("/");

    let wsl_output_path = output
        .canonicalize()
        .expect("failed to canonicalize output directory path")
        .join("initrd.tar")
        .components()
        .map(|c| match c {
            std::path::Component::Prefix(_) => "/mnt/c",
            std::path::Component::RootDir => "",
            std::path::Component::CurDir => ".",
            std::path::Component::ParentDir => "..",
            std::path::Component::Normal(s) => s
                .to_str()
                .expect("failed to convert os path segment to str"),
        })
        .join("/");

    let mut command = cmd
        .args(vec!["--cd", &wsl_path, "tar", "-cf", &wsl_output_path, "*"])
        .spawn()
        .expect("failed to run tar command");

    let result = command.wait().expect("tar command produced error");

    result
}

pub fn main() {
    println!("cargo:rerun-if-changed=initrd/");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    make_tar(out.clone());

    let wsl_path = current_dir()
        .expect("failed to get current directory")
        .join("initrd")
        .canonicalize()
        .expect("failed to canonicalize current_directory path")
        .components()
        .map(|c| match c {
            std::path::Component::Prefix(_) => {
                // We just assume this is C:. Your build is probably broken if you're building on another drive or a
                // network share. Sorry. I just can't be assed to handle this kind of thing well. If you made it to this
                // point debugging a build issue, you're probably smart enough to fix it as well.
                "/mnt/c"
            }
            std::path::Component::RootDir => "",
            std::path::Component::CurDir => ".",
            std::path::Component::ParentDir => "..",
            std::path::Component::Normal(s) => s
                .to_str()
                .expect("failed to convert os path segment to str"),
        })
        .join("/");

    std::fs::write(PathBuf::from("out.log"), format!("{}", wsl_path))
        .expect("failed to write build log");
}
