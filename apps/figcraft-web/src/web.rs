//! The browser shell: web `Services` and the eframe web runner.

use figcraft_collab_net::pkce::Back;
use figcraft_engine::Session;
use figcraft_ui_egui::home::Section;
use figcraft_ui_egui::{FigApp, Services};
use serde_json::json;
use wasm_bindgen::JsCast as _;

const CANVAS_ID: &str = "figcraft_canvas";
const LOADING_ID: &str = "figcraft_loading";

pub fn start() {
    eframe::WebLogger::init(log::LevelFilter::Info).ok();
    wasm_bindgen_futures::spawn_local(async {
        let Some(document) = web_sys::window().and_then(|w| w.document()) else {
            log::error!("no document");
            return;
        };
        let Some(canvas) = document.get_element_by_id(CANVAS_ID).and_then(|e| e.dyn_into::<web_sys::HtmlCanvasElement>().ok()) else {
            log::error!("missing <canvas id=\"{CANVAS_ID}\">");
            return;
        };
        let mut options = eframe::WebOptions::default();
        // `?webgl`: force the WebGL2 backend (troubleshooting, and headless browsers whose WebGPU
        // adapter request returns nothing).
        if query().contains("webgl")
            && let eframe::egui_wgpu::WgpuSetup::CreateNew(create) = &mut options.wgpu_options.wgpu_setup
        {
            create.instance_descriptor.backends = eframe::wgpu::Backends::GL;
        }
        let result = eframe::WebRunner::new()
            .start(
                canvas,
                options,
                Box::new(|cc| {
                    if let Some(rs) = &cc.wgpu_render_state {
                        log::info!("figcraft-web: wgpu backend {:?}", rs.adapter.get_info().backend);
                    }
                    let reduce_motion = web_sys::window().and_then(|w| w.match_media("(prefers-reduced-motion: reduce)").ok().flatten());
                    // Nothing open at first: the home screen (behind the sign-in on a server with
                    // accounts), with the preferences this browser kept.
                    let mut session = Session::empty();
                    if let Some(prefs) = load_prefs() {
                        session.prefs = prefs;
                    }
                    // Live sessions: the browser joins sessions a desktop app hosts; whatever arrives
                    // on the socket wakes the page for a frame.
                    let ctx = cc.egui_ctx.clone();
                    session.live.install(Box::new(figcraft_collab_net::NetLink::new(std::sync::Arc::new(move || ctx.request_repaint()))));
                    let mut fig = FigApp::new(session, Box::new(WebServices { reduce_motion, ctx: cc.egui_ctx.clone() }));
                    fig.ui.login_gate = true;
                    // Back from a provider's sign-in page (`?code=…&state=…`): finished on the first frame.
                    Ok(Box::new(WebShell { fig, back: figcraft_collab_net::redirect_back() }))
                }),
            )
            .await;
        if let Some(el) = document.get_element_by_id(LOADING_ID) {
            match result {
                Ok(()) => el.remove(),
                Err(e) => el.set_inner_html(&format!("<p>FigCraft failed to start: {e:?}</p><p>A browser with WebGPU or WebGL2 is required.</p>")),
            }
        }
    });
}

/// Where the browser keeps the preferences: the page's local storage.
const PREFS_KEY: &str = "figcraft.prefs";

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|w| w.local_storage().ok().flatten())
}

/// The preferences this browser kept (with your sign-ins and this device's key), if any. A
/// browser that keeps nothing (private windows, storage turned off) starts afresh each time.
fn load_prefs() -> Option<figcraft_engine::Prefs> {
    let text = local_storage()?.get_item(PREFS_KEY).ok().flatten()?;
    serde_json::from_str(&text).map_err(|e| log::warn!("preferences: the kept ones can't be read ({e}); starting afresh")).ok()
}

fn query() -> String {
    web_sys::window().and_then(|w| w.location().search().ok()).unwrap_or_default()
}

struct WebShell {
    fig: FigApp,
    /// A sign-in the provider sent this page back from, to finish with the server.
    back: Option<Result<Back, String>>,
}

impl WebShell {
    /// Hand the code the provider sent back to the server (`account.signIn`, flow `code`); the
    /// home screen shows the server's page.
    fn finish_sign_in(&mut self, ctx: &egui::Context) {
        let Some(back) = self.back.take() else { return };
        self.fig.ui.home_view.section = Section::Server(0);
        match back {
            Ok(b) => {
                let params = json!({
                    "server": b.server, "provider": b.provider, "flow": "code",
                    "code": b.code, "verifier": b.verifier, "redirectUri": b.redirect_uri,
                });
                self.fig.run_background(ctx, "account.signIn", params, Box::new(|_, _, _| {}));
            }
            Err(why) => {
                self.fig.session.accounts.last = Some(Err(why.clone()));
                self.fig.toast(why);
            }
        }
    }
}

impl eframe::App for WebShell {
    // `FigApp::ui` runs its own per-frame logic first (fonts, theme), like the desktop app.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.finish_sign_in(&ctx);
        self.fig.ui(ui);
    }
}

/// Browser services. Open dialogs return nothing for now (the trait's defaults); files are saved
/// as downloads. Copies go to the system clipboard through egui's output; pastes arrive as paste
/// events with their text (a page can't read the clipboard when it likes).
struct WebServices {
    /// `prefers-reduced-motion: reduce` (it follows the setting while the page is open).
    reduce_motion: Option<web_sys::MediaQueryList>,
    ctx: egui::Context,
}

impl Services for WebServices {
    fn downloads(&self) -> bool {
        true
    }
    /// A Blob behind a temporary `<a download>` link, clicked and removed.
    fn download(&mut self, name: &str, bytes: &[u8]) -> bool {
        match download(name, bytes) {
            Ok(()) => true,
            Err(e) => {
                log::error!("couldn't download {name}: {e:?}");
                false
            }
        }
    }
    fn clipboard_set_text(&mut self, s: &str) {
        figcraft_ui_egui::egui_copy_text(&self.ctx, s);
    }
    fn clipboard_set_png(&mut self, w: u32, h: u32, rgba: &[u8]) {
        figcraft_ui_egui::egui_copy_png(&self.ctx, w, h, rgba);
    }
    fn open_url(&mut self, url: &str) {
        let Some(window) = web_sys::window() else { return };
        if let Err(e) = window.open_with_url_and_target(url, "_blank") {
            log::error!("couldn't open {url}: {e:?}");
        }
    }
    fn reduce_motion(&self) -> bool {
        self.reduce_motion.as_ref().is_some_and(web_sys::MediaQueryList::matches)
    }
    /// Kept in the page's local storage: your sign-ins (session tokens) and this device's key
    /// for encrypted files with them, so a reload keeps you signed in. Weaker than the desktop
    /// app's keychain: anything running on this site, and anyone with this browser profile, can
    /// read them (`docs/server-accounts.md`).
    fn save_prefs(&mut self, prefs: &figcraft_engine::Prefs) {
        let Some(storage) = local_storage() else { return };
        let saved =
            serde_json::to_string(prefs).map_err(|e| e.to_string()).and_then(|t| storage.set_item(PREFS_KEY, &t).map_err(|e| format!("{e:?}")));
        if let Err(e) = saved {
            log::warn!("preferences: not kept in this browser: {e}");
        }
    }
    /// The browser's language (`navigator.language`).
    fn system_language(&self) -> Option<String> {
        web_sys::window().and_then(|w| w.navigator().language())
    }
    /// The Gamepad API's controllers with the standard mapping (its button order is the layout's;
    /// others are skipped). Browsers list controllers once one of their buttons is pressed.
    fn gamepad_held(&mut self) -> u32 {
        let Some(pads) = web_sys::window().and_then(|w| w.navigator().get_gamepads().ok()) else { return 0 };
        let mut held = 0;
        for pad in pads.iter().filter_map(|p| p.dyn_into::<web_sys::Gamepad>().ok()) {
            if pad.mapping() != web_sys::GamepadMappingType::Standard {
                continue;
            }
            for (i, b) in pad.buttons().iter().take(32).enumerate() {
                if b.dyn_into::<web_sys::GamepadButton>().is_ok_and(|b| b.pressed()) {
                    held |= 1 << i;
                }
            }
        }
        held
    }
}

fn download(name: &str, bytes: &[u8]) -> Result<(), wasm_bindgen::JsValue> {
    let window = web_sys::window().ok_or("no window")?;
    let document = window.document().ok_or("no document")?;
    let body = document.body().ok_or("no body")?;
    let parts = js_sys::Array::of1(&js_sys::Uint8Array::from(bytes));
    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &{
        let o = web_sys::BlobPropertyBag::new();
        o.set_type("application/octet-stream");
        o
    })?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)?;
    let a: web_sys::HtmlAnchorElement = document.create_element("a")?.dyn_into()?;
    a.set_href(&url);
    a.set_download(name);
    body.append_child(&a)?;
    a.click();
    a.remove();
    // Revoked later, not at once: some browsers cancel a download whose URL goes before it starts.
    let revoke = wasm_bindgen::closure::Closure::once_into_js(move || {
        let _ = web_sys::Url::revoke_object_url(&url);
    });
    // Without the timer the URL just stays until the page closes.
    let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(revoke.unchecked_ref(), REVOKE_DOWNLOAD_MS);
    Ok(())
}

/// How long a download's object URL is kept (milliseconds).
const REVOKE_DOWNLOAD_MS: i32 = 40_000;
