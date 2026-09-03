use std::{process::Command, ptr};

use secrecy::SecretString;
use serde::Deserialize;

use super::write_output;

#[unsafe(no_mangle)]
pub extern "C" fn tunnel_get_kubeconfig(out_data: *mut *mut u8, out_len: *mut usize) -> bool {
    if out_data.is_null() || out_len.is_null() {
        return false;
    }
    unsafe {
        *out_data = ptr::null_mut();
        *out_len = 0;
    }
    let mut config = match kube::config::Kubeconfig::read() {
        Ok(config) => config,
        Err(error) => {
            write_output(out_data, out_len, error.to_string().into_bytes());
            return false;
        }
    };
    #[derive(Deserialize)]
    struct ExecCredential {
        status: Option<ExecCredentialStatus>,
    }
    #[derive(Deserialize)]
    struct ExecCredentialStatus {
        token: Option<String>,
    }

    // Execute auth plugins in the containing app. The sandboxed extension gets
    // only the resulting short-lived bearer token, never an exec command.
    for auth in &mut config.auth_infos {
        let Some(info) = auth.auth_info.as_mut() else {
            continue;
        };
        let Some(exec) = info.exec.as_ref() else {
            continue;
        };
        let Some(command) = exec.command.clone() else {
            continue;
        };
        let args = exec.args.clone().unwrap_or_default();
        let mut process = Command::new(&command);
        process.args(args);
        if let Some(env) = &exec.env {
            for variable in env {
                if let (Some(name), Some(value)) = (variable.get("name"), variable.get("value")) {
                    process.env(name, value);
                }
            }
        }
        let output = match process.output() {
            Ok(output) => output,
            Err(error) => {
                write_output(
                    out_data,
                    out_len,
                    format!("auth exec {command}: {error}").into_bytes(),
                );
                return false;
            }
        };
        if !output.status.success() {
            write_output(
                out_data,
                out_len,
                String::from_utf8_lossy(&output.stderr)
                    .into_owned()
                    .into_bytes(),
            );
            return false;
        }
        let credential: ExecCredential = match serde_json::from_slice(&output.stdout) {
            Ok(credential) => credential,
            Err(error) => {
                write_output(
                    out_data,
                    out_len,
                    format!("invalid auth exec output: {error}").into_bytes(),
                );
                return false;
            }
        };
        let Some(token) = credential.status.and_then(|status| status.token) else {
            write_output(
                out_data,
                out_len,
                format!("auth exec {command} returned no token").into_bytes(),
            );
            return false;
        };
        info.token = Some(SecretString::new(token.into()));
        info.exec = None;
    }

    match serde_yaml::to_string(&config) {
        Ok(yaml) => {
            write_output(out_data, out_len, yaml.into_bytes());
            true
        }
        Err(error) => {
            write_output(out_data, out_len, error.to_string().into_bytes());
            false
        }
    }
}
