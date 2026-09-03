//! Small C ABI used by the macOS Packet Tunnel extension.
//!
//! The current implementation deliberately drops packets. Replace
//! `process_packet` with the real tunnel engine once the transport is wired in.

use std::{
    ptr, slice,
    sync::{Mutex, OnceLock},
};

mod auth;
mod tunnel;

use tokio::sync::{mpsc, watch};

type PacketCallback = extern "C" fn(data: *const u8, len: usize, protocol: u32);
type SettingsCallback = extern "C" fn(data: *const u8, len: usize);

struct TunnelEngine {
    packets: mpsc::Sender<Vec<u8>>,
    stop: watch::Sender<bool>,
}

static ENGINE: OnceLock<Mutex<Option<TunnelEngine>>> = OnceLock::new();

fn engine() -> &'static Mutex<Option<TunnelEngine>> {
    ENGINE.get_or_init(|| Mutex::new(None))
}

#[repr(C)]
pub struct TunnelPacket {
    pub data: *mut u8,
    pub len: usize,
    pub protocol: u32,
}

impl TunnelPacket {
    fn empty() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
            protocol: 0,
        }
    }
}

/// Processes one IP packet received from NEPacketTunnelFlow.
///
/// Returning an empty packet means "nothing to write back". The transport
/// implementation should eventually send this packet to the remote tunnel and
/// expose received packets through a separate callback/queue API.
#[unsafe(no_mangle)]
pub extern "C" fn tunnel_process_packet(
    data: *const u8,
    len: usize,
    protocol: u32,
) -> TunnelPacket {
    if data.is_null() || len == 0 {
        return TunnelPacket::empty();
    }

    let packet = unsafe { slice::from_raw_parts(data, len) };
    let _protocol = protocol;

    let Some(engine) = engine()
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|e| e.packets.clone()))
    else {
        return TunnelPacket::empty();
    };
    // This function is called from Swift's packet-flow callback; never block it.
    let _ = engine.try_send(packet.to_vec());
    TunnelPacket::empty()
}

/// Frees a packet allocated by Rust. Kept for the eventual output API.
#[unsafe(no_mangle)]
pub extern "C" fn tunnel_free_packet(data: *mut u8, len: usize) {
    if !data.is_null() {
        unsafe {
            drop(Vec::from_raw_parts(data, len, len));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tunnel_start(
    context_data: *const u8,
    context_len: usize,
    namespace_data: *const u8,
    namespace_len: usize,
    kubeconfig_data: *const u8,
    kubeconfig_len: usize,
    pod_data: *const u8,
    pod_len: usize,
    callback: Option<PacketCallback>,
    settings_callback: Option<SettingsCallback>,
) -> bool {
    let Some(callback) = callback else {
        eprintln!("[tunnel] start rejected: callback missing");
        return false;
    };
    let Some(settings_callback) = settings_callback else {
        eprintln!("[tunnel] start rejected: settings callback missing");
        return false;
    };
    if context_data.is_null()
        || namespace_data.is_null()
        || kubeconfig_data.is_null()
        || pod_data.is_null()
        || context_len == 0
        || namespace_len == 0
        || kubeconfig_len == 0
        || pod_len == 0
    {
        eprintln!("[tunnel] start rejected: context, namespace, or pod missing");
        return false;
    }
    let Ok(context) =
        std::str::from_utf8(unsafe { slice::from_raw_parts(context_data, context_len) })
    else {
        eprintln!("[tunnel] invalid context UTF-8");
        return false;
    };
    let Ok(namespace) =
        std::str::from_utf8(unsafe { slice::from_raw_parts(namespace_data, namespace_len) })
    else {
        eprintln!("[tunnel] invalid namespace UTF-8");
        return false;
    };
    let Ok(kubeconfig) =
        std::str::from_utf8(unsafe { slice::from_raw_parts(kubeconfig_data, kubeconfig_len) })
    else {
        eprintln!("[tunnel] invalid kubeconfig UTF-8");
        return false;
    };
    let Ok(pod) = std::str::from_utf8(unsafe { slice::from_raw_parts(pod_data, pod_len) }) else {
        eprintln!("[tunnel] invalid pod UTF-8");
        return false;
    };
    eprintln!("[tunnel] starting context={context} namespace={namespace} pod={pod}");

    let (packets, packet_rx) = mpsc::channel::<Vec<u8>>(256);
    let (stop, stop_rx) = watch::channel(false);
    let context = context.to_owned();
    let namespace = namespace.to_owned();
    let kubeconfig = kubeconfig.to_owned();
    let pod = pod.to_owned();
    let Ok(mut guard) = engine().lock() else {
        return false;
    };
    if guard.is_some() {
        eprintln!("[tunnel] start rejected: tunnel already running");
        return false;
    }
    let stop_for_thread = stop.clone();
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        eprintln!("[tunnel] runtime started");
        runtime.block_on(tunnel::run_tunnel(
            context,
            namespace,
            kubeconfig,
            pod,
            packet_rx,
            stop_rx,
            callback,
            settings_callback,
        ));
        eprintln!("[tunnel] runtime stopped");
        let _ = stop_for_thread.send(true);
        if let Ok(mut guard) = engine().lock() {
            *guard = None;
        }
    });
    *guard = Some(TunnelEngine { packets, stop });
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn tunnel_stop() {
    eprintln!("[tunnel] stop requested");
    if let Ok(mut guard) = engine().lock() {
        if let Some(engine) = guard.take() {
            let _ = engine.stop.send(true);
        }
    }
}

fn notify_settings_error(callback: SettingsCallback, message: &str) {
    let payload = serde_json::json!({ "error": message }).to_string();
    callback(payload.as_ptr(), payload.len());
}

pub(crate) fn write_output(out_data: *mut *mut u8, out_len: *mut usize, mut data: Vec<u8>) {
    unsafe {
        *out_data = data.as_mut_ptr();
        *out_len = data.len();
    }
    std::mem::forget(data);
}

/// Returns kubeconfig context names as a JSON array.
#[unsafe(no_mangle)]
pub extern "C" fn tunnel_get_contexts(out_data: *mut *mut u8, out_len: *mut usize) -> bool {
    if out_data.is_null() || out_len.is_null() {
        return false;
    }
    unsafe {
        *out_data = ptr::null_mut();
        *out_len = 0;
    }

    let contexts = match crate::pods::kubeconfig_contexts() {
        Ok(contexts) => contexts,
        Err(error) => {
            write_output(out_data, out_len, error.to_string().into_bytes());
            return false;
        }
    };
    match serde_json::to_vec(&contexts) {
        Ok(json) => {
            write_output(out_data, out_len, json);
            true
        }
        Err(error) => {
            write_output(out_data, out_len, error.to_string().into_bytes());
            false
        }
    }
}

/// Returns the merged kubeconfig as YAML for use by the sandboxed extension.

/// Returns all-namespace Pods for one kubeconfig context as JSON.
#[unsafe(no_mangle)]
pub extern "C" fn tunnel_get_pods(
    context_data: *const u8,
    context_len: usize,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> bool {
    if context_data.is_null() || out_data.is_null() || out_len.is_null() {
        return false;
    }
    let context =
        match std::str::from_utf8(unsafe { slice::from_raw_parts(context_data, context_len) }) {
            Ok(context) => context.to_owned(),
            Err(error) => {
                write_output(out_data, out_len, error.to_string().into_bytes());
                return false;
            }
        };
    unsafe {
        *out_data = ptr::null_mut();
        *out_len = 0;
    }

    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    let result = runtime.block_on(crate::pods::get_pods(context));
    match serde_json::to_vec(&result) {
        Ok(json) => {
            let success = result.error.is_none();
            write_output(out_data, out_len, json);
            success
        }
        Err(error) => {
            write_output(out_data, out_len, error.to_string().into_bytes());
            false
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tunnel_free_buffer(data: *mut u8, len: usize) {
    if !data.is_null() {
        unsafe {
            drop(Vec::from_raw_parts(data, len, len));
        }
    }
}
