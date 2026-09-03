use std::error::Error;

use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client, Config, api::ListParams};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(serde::Serialize)]
pub struct ContextPods {
    pub context: String,
    pub namespace: String,
    pub pods: Vec<Pod>,
    pub error: Option<String>,
}

pub fn kubeconfig_contexts() -> Result<Vec<String>> {
    Ok(kube::config::Kubeconfig::read()?
        .contexts
        .into_iter()
        .map(|context| context.name)
        .collect())
}

pub async fn get_pods(context_name: String) -> ContextPods {
    let kubeconfig = match kube::config::Kubeconfig::read() {
        Ok(config) => config,
        Err(error) => {
            return ContextPods {
                context: context_name,
                namespace: "all namespaces".to_string(),
                pods: Vec::new(),
                error: Some(error.to_string()),
            };
        }
    };
    pods_for_context(kubeconfig, context_name).await
}

async fn pods_for_context(
    kubeconfig: kube::config::Kubeconfig,
    context_name: String,
) -> ContextPods {
    let options = kube::config::KubeConfigOptions {
        context: Some(context_name.clone()),
        cluster: None,
        user: None,
    };

    let result = async {
        let config = Config::from_custom_kubeconfig(kubeconfig, &options).await?;
        let namespace = config.default_namespace.clone();
        let client = Client::try_from(config)?;
        let pods: Api<Pod> = Api::all(client);
        let list = pods.list(&ListParams::default()).await?;
        let tunnel_pods = list
            .items
            .into_iter()
            .filter(|pod| {
                pod.metadata
                    .annotations
                    .as_ref()
                    .is_some_and(|annotations| annotations.contains_key("tunnel/port"))
            })
            .collect();
        Ok::<_, Box<dyn Error + Send + Sync>>((namespace, tunnel_pods))
    }
    .await;

    match result {
        Ok((namespace, pods)) => ContextPods {
            context: context_name,
            namespace,
            pods,
            error: None,
        },
        Err(error) => ContextPods {
            context: context_name,
            namespace: "all namespaces".to_string(),
            pods: Vec::new(),
            error: Some(error.to_string()),
        },
    }
}
