//! The operating system's keychain for this install's device secret (sealed files on servers with
//! accounts, `docs/accounts-and-e2e.md` › *Keys*): the Windows Credential Manager, the macOS
//! keychain, or the Secret Service (GNOME Keyring, KWallet) on Linux and the BSDs, through the
//! `keyring` crate. The desktop app installs it into the engine ([`os_keychain`]); where there is
//! none (another OS, no Secret Service running, a keychain that refuses) the engine keeps the
//! secret with the preferences instead, and says so (`account.devices` → `keyStore`).

use figcraft_engine::devices::Keychain;

/// The keychain entry: one per OS user (every FigCraft install of that user shares the device).
const SERVICE: &str = "FigCraft";
const USER: &str = "device-key";

/// This OS's keychain, where there is one this build can use.
pub fn os_keychain() -> Option<Box<dyn Keychain>> {
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
    {
        Some(Box::new(os::OsKeychain))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
    {
        None
    }
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
mod os {
    use figcraft_engine::devices::Keychain;
    use zeroize::Zeroizing;

    use super::{SERVICE, USER};

    pub(super) struct OsKeychain;

    fn entry() -> Result<keyring::Entry, String> {
        keyring::Entry::new(SERVICE, USER).map_err(|e| format!("no keychain: {e}"))
    }

    impl Keychain for OsKeychain {
        fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            match entry()?.get_secret() {
                Ok(s) => Ok(Some(Zeroizing::new(s))),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(format!("the keychain can't be read: {e}")),
            }
        }

        fn store(&self, secret: &[u8]) -> Result<(), String> {
            entry()?.set_secret(secret).map_err(|e| format!("the keychain refused the key: {e}"))
        }
    }
}
