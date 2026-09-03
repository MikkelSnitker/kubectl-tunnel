use futures::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, watch},
    time::{self, Duration},
};

use super::{PacketCallback, SettingsCallback, notify_settings_error};

pub(super) async fn run_tunnel(
    context_name: String,
    namespace: String,
    kubeconfig_yaml: String,
    pod_name: String,
    mut packets: mpsc::Receiver<Vec<u8>>,
    mut stop: watch::Receiver<bool>,
    callback: PacketCallback,
    settings_callback: SettingsCallback,
) {
    eprintln!("[tunnel] loading kubeconfig context={context_name}");
    let Ok(kubeconfig) = kube::config::Kubeconfig::from_yaml(&kubeconfig_yaml) else {
        notify_settings_error(settings_callback, "failed to parse serialized kubeconfig");
        return;
    };
    let options = kube::config::KubeConfigOptions {
        context: Some(context_name.clone()),
        cluster: None,
        user: None,
    };
    let config = match kube::Config::from_custom_kubeconfig(kubeconfig, &options).await {
        Ok(config) => config,
        Err(error) => {
            notify_settings_error(
                settings_callback,
                &format!("failed to load Kubernetes context: {error}"),
            );
            return;
        }
    };
    let client = match kube::Client::try_from(config) {
        Ok(client) => client,
        Err(error) => {
            notify_settings_error(
                settings_callback,
                &format!("failed to create Kubernetes client: {error}"),
            );
            return;
        }
    };
    eprintln!("[tunnel] finding pod={pod_name} namespace={namespace}");
    let api: kube::Api<k8s_openapi::api::core::v1::Pod> = kube::Api::namespaced(client, &namespace);
    let Ok(pod) = api.get(&pod_name).await else {
        notify_settings_error(settings_callback, "pod lookup failed");
        return;
    };
    let Some(annotations) = pod.metadata.annotations.as_ref() else {
        notify_settings_error(settings_callback, "pod has no tunnel annotations");
        return;
    };
    let Some(port) = annotations
        .get("tunnel/port")
        .and_then(|p| p.parse::<u16>().ok())
    else {
        notify_settings_error(settings_callback, "pod has no valid tunnel/port annotation");
        return;
    };
    let routes: Vec<String> = annotations
        .get("tunnel/routes")
        .into_iter()
        .flat_map(|value| value.lines())
        .map(str::trim)
        .filter(|route| !route.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    // DNS is represented as `server: domain, domain` entries.
    let mut dns_servers = Vec::new();
    let mut dns_domains = Vec::new();
    if let Some(dns) = annotations.get("tunnel/dns") {
        for line in dns.lines() {
            let Some((server, domains)) = line.split_once(": ") else {
                continue;
            };
            let server = server.trim().trim_end_matches(':').to_owned();
            if server.parse::<std::net::IpAddr>().is_err() {
                continue;
            }
            dns_servers.push(server);
            dns_domains.extend(
                domains
                    .split(',')
                    .map(str::trim)
                    .filter(|domain| !domain.is_empty())
                    .map(ToOwned::to_owned),
            );
        }
    }
    eprintln!("[tunnel] opening port-forward namespace={namespace} pod={pod_name} port={port}");
    let Ok(mut forwarder) = api.portforward(&pod_name, &[port]).await else {
        notify_settings_error(settings_callback, "port-forward failed");
        return;
    };
    let Some(stream) = forwarder.take_stream(port) else {
        notify_settings_error(settings_callback, "port-forward stream unavailable");
        return;
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    eprintln!("[tunnel] sending handshake");
    let request = crate::handshake::HandshakeRequest {
        version: 2,
        address: std::net::Ipv4Addr::UNSPECIFIED,
    };
    if writer.write_all(&Vec::<u8>::from(request)).await.is_err() {
        notify_settings_error(settings_callback, "handshake write failed");
        return;
    }
    let mut handshake = [0u8; 16];
    if reader.read_exact(&mut handshake).await.is_err() {
        notify_settings_error(settings_callback, "handshake read failed");
        return;
    }
    let Ok(response) = crate::handshake::HandshakeResponse::try_from(&handshake[..]) else {
        notify_settings_error(settings_callback, "invalid handshake response");
        return;
    };
    let settings = serde_json::json!({
        "localAddress": response.local_address.to_string(),
        "remoteAddress": response.remote_address.to_string(),
        "netmask": response.netmask.to_string(),
        "mtu": response.mtu_size,
        "routes": routes,
        "dnsServers": dns_servers,
        "dnsDomains": dns_domains,
    });
    if let Ok(json) = serde_json::to_vec(&settings) {
        settings_callback(json.as_ptr(), json.len());
    }
    eprintln!(
        "[tunnel] connected local={} remote={} netmask={} mtu={}",
        response.local_address, response.remote_address, response.netmask, response.mtu_size
    );
    let mtu = response.mtu_size;
    let mut reader = tokio_util::codec::FramedRead::new(reader, crate::codec::TUNCodec(mtu, false));
    let mut writer =
        tokio_util::codec::FramedWrite::new(writer, crate::codec::TUNCodec(mtu, false));
    let heartbeat_enabled = response.version >= 2;
    let mut heartbeat = time::interval(Duration::from_secs(20));

    loop {
        tokio::select! {
            _ = heartbeat.tick(), if heartbeat_enabled => {
                if writer.send(bytes::Bytes::from_static(&[crate::codec::HEARTBEAT])).await.is_err() {
                    eprintln!("[tunnel] heartbeat failed");
                    break;
                }
            },
            _ = stop.changed() => break,
            packet = packets.recv() => match packet {
                Some(packet) => {
                    if writer.send(bytes::Bytes::from(packet)).await.is_err() {
                        eprintln!("[tunnel] send packet failed");
                        notify_settings_error(settings_callback, "tunnel transport disconnected while sending");
                        break;
                    }
                },
                None => break,
            },
            packet = reader.next() => match packet {
                Some(Ok(packet)) => {
                    let protocol = match packet.first().map(|b| b >> 4) { Some(4) => 2, Some(6) => 30, _ => continue };
                    callback(packet.as_ptr(), packet.len(), protocol);
                },
                Some(Err(error)) => {
                    eprintln!("[tunnel] receive packet failed: {error}");
                    notify_settings_error(settings_callback, "tunnel transport disconnected while receiving");
                    break;
                },
                None => {
                    eprintln!("[tunnel] remote connection closed");
                    notify_settings_error(settings_callback, "tunnel remote connection closed");
                    break;
                },
            },
        }
    }
}
