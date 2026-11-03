use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use std::path::PathBuf;
use vault_core::Vault;
use zeroize::Zeroizing;
#[derive(Parser)]
#[command(version, about = "Experimental encrypted WebDAV vault")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        path: PathBuf,
    },
    Unlock {
        path: PathBuf,
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Init { path } => {
            let p = Zeroizing::new(rpassword::prompt_password("New password: ")?);
            let q = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
            if p.is_empty() || *p != *q {
                bail!("empty or mismatched passwords");
            }
            Vault::create(&path, p.as_bytes())?;
            println!("Vault created at {}", path.display());
        }
        Command::Unlock { path, port } => {
            let p = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
            let vault = Vault::open(&path, p.as_bytes())?;
            drop(p);
            let mut bytes = [0u8; 24];
            OsRng.fill_bytes(&mut bytes);
            let password =
                Zeroizing::new(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
            println!("Temporary WebDAV password: {}\nStop with Ctrl-C; disconnect the network volume in Finder/Explorer.", password.as_str());
            vault_dav::serve(
                vault_fs::Store { vault, dir: path },
                "vault",
                &password,
                port,
            )
            .await?;
        }
    }
    Ok(())
}
