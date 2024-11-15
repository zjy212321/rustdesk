use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
