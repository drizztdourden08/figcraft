//! FigCraft in the browser.
//!
//! Runs the same [`figcraft_ui_egui::FigApp`] as the desktop app through eframe's web runner
//! (wgpu: WebGPU where available, WebGL2 otherwise). Build with `trunk build --release` from this
//! directory; the site lands in `dist/web` (see `packaging/web/README.md`).
//!
//! Differences from the desktop app:
//! - no TCP control server (browsers can't listen on sockets);
//! - no native file dialogs yet: the session starts with one new document;
//! - links open in a new browser tab;
//! - live sessions: it joins sessions a desktop app hosts (File ▸ Join live session…) but can't
//!   host one. A page served over `https://` can only reach sessions on the same computer
//!   (browsers block `ws://` from secure pages); serve it over `http://` on a trusted network to
//!   join from other machines;
//! - servers: a build made with `FIGCRAFT_DEFAULT_SERVER=wss://host/` (what a server hosts,
//!   `packaging/web/package.sh --server`) works with that server only, next to local files.
//!   Signing in with a username and password works as in the desktop app; with an identity
//!   provider, the page goes to the provider's sign-in page and comes back with a code
//!   (`?code=…&state=…`, finished on the first frame and taken off the address), when the server
//!   lists the page in `web_redirect_uris` (`docs/server-accounts.md`).
//!
//! URL query flag: `?webgl` forces the WebGL2 backend instead of WebGPU.

#[cfg(target_arch = "wasm32")]
mod web;

#[cfg(target_arch = "wasm32")]
fn main() {
    web::start();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("figcraft-web only runs in the browser: build it with `trunk build --release` in apps/figcraft-web");
}
