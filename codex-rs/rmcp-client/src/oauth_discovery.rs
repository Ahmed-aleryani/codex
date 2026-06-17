use reqwest::Client;
use reqwest::StatusCode;
use reqwest::Url;
use rmcp::transport::auth::AuthorizationMetadata;
use serde::Deserialize;
use tracing::debug;

const OAUTH_DISCOVERY_HEADER: &str = "MCP-Protocol-Version";
const OAUTH_DISCOVERY_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone)]
pub(crate) struct ProtectedResourceOAuthDiscovery {
    pub authorization_metadata: AuthorizationMetadata,
    pub scopes_supported: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ResourceMetadata {
    #[serde(default)]
    authorization_server: Option<String>,
    #[serde(default)]
    authorization_servers: Option<Vec<String>>,
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
}

pub(crate) async fn discover_protected_resource_oauth_metadata(
    client: &Client,
    base_url: &Url,
) -> Option<ProtectedResourceOAuthDiscovery> {
    for resource_metadata_url in protected_resource_metadata_urls(base_url) {
        let resource_metadata = match fetch_resource_metadata(client, resource_metadata_url).await {
            Ok(Some(metadata)) => metadata,
            Ok(None) => continue,
            Err(err) => {
                debug!("protected resource metadata discovery failed: {err:?}");
                continue;
            }
        };

        for authorization_server in authorization_servers(&resource_metadata) {
            for metadata_url in authorization_metadata_urls(&authorization_server) {
                match fetch_authorization_metadata(client, metadata_url).await {
                    Ok(Some(authorization_metadata)) => {
                        return Some(ProtectedResourceOAuthDiscovery {
                            authorization_metadata,
                            scopes_supported: resource_metadata.scopes_supported.clone(),
                        });
                    }
                    Ok(None) => {}
                    Err(err) => {
                        debug!("authorization metadata discovery failed: {err:?}");
                    }
                }
            }
        }
    }

    None
}

async fn fetch_resource_metadata(
    client: &Client,
    resource_metadata_url: Url,
) -> reqwest::Result<Option<ResourceMetadata>> {
    let response = client
        .get(resource_metadata_url)
        .header(OAUTH_DISCOVERY_HEADER, OAUTH_DISCOVERY_VERSION)
        .send()
        .await?;

    if response.status() != StatusCode::OK {
        return Ok(None);
    }

    response.json::<ResourceMetadata>().await.map(Some)
}

async fn fetch_authorization_metadata(
    client: &Client,
    metadata_url: Url,
) -> reqwest::Result<Option<AuthorizationMetadata>> {
    let response = client
        .get(metadata_url)
        .header(OAUTH_DISCOVERY_HEADER, OAUTH_DISCOVERY_VERSION)
        .send()
        .await?;

    if response.status() != StatusCode::OK {
        return Ok(None);
    }

    response.json::<AuthorizationMetadata>().await.map(Some)
}

fn authorization_servers(resource_metadata: &ResourceMetadata) -> Vec<Url> {
    let mut candidates = Vec::new();
    if let Some(server) = &resource_metadata.authorization_server {
        candidates.push(server.as_str());
    }
    if let Some(servers) = &resource_metadata.authorization_servers {
        candidates.extend(servers.iter().map(String::as_str));
    }

    candidates
        .into_iter()
        .filter_map(|server| Url::parse(server.trim()).ok())
        .collect()
}

fn protected_resource_metadata_urls(base_url: &Url) -> Vec<Url> {
    let base_path = base_url.path();
    let trimmed = base_path.trim_start_matches('/').trim_end_matches('/');
    let canonical = "/.well-known/oauth-protected-resource".to_string();
    let mut candidates = Vec::new();

    let mut push_unique = |path: String| {
        let mut url = base_url.clone();
        url.set_query(None);
        url.set_fragment(None);
        url.set_path(&path);
        if !candidates.contains(&url) {
            candidates.push(url);
        }
    };

    if trimmed.is_empty() {
        push_unique(canonical);
        return candidates;
    }

    if base_path.ends_with('/') {
        push_unique(format!("{canonical}/{trimmed}/"));
    }
    push_unique(format!("{canonical}/{trimmed}"));
    push_unique(format!("/{trimmed}/.well-known/oauth-protected-resource"));
    push_unique(canonical);

    candidates
}

fn authorization_metadata_urls(authorization_server: &Url) -> Vec<Url> {
    let trimmed = authorization_server
        .path()
        .trim_start_matches('/')
        .trim_end_matches('/');
    let mut candidates = Vec::new();

    let mut push_unique = |path: String| {
        let mut url = authorization_server.clone();
        url.set_query(None);
        url.set_fragment(None);
        url.set_path(&path);
        if !candidates.contains(&url) {
            candidates.push(url);
        }
    };

    if trimmed.is_empty() {
        push_unique("/.well-known/oauth-authorization-server".to_string());
        push_unique("/.well-known/openid-configuration".to_string());
        return candidates;
    }

    push_unique(format!("/.well-known/oauth-authorization-server/{trimmed}"));
    push_unique(format!("/.well-known/openid-configuration/{trimmed}"));
    push_unique(format!("/{trimmed}/.well-known/oauth-authorization-server"));
    push_unique(format!("/{trimmed}/.well-known/openid-configuration"));
    push_unique("/.well-known/oauth-authorization-server".to_string());
    push_unique("/.well-known/openid-configuration".to_string());

    candidates
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Json;
    use axum::Router;
    use axum::routing::get;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use tokio::task::JoinHandle;

    use super::*;

    struct TestServer {
        url: String,
        handle: JoinHandle<()>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_protected_resource_discovery_server() -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener should have address");
        let issuer = format!("http://{address}/issuer");
        let authorization_endpoint = format!("http://{address}/oauth/authorize");
        let token_endpoint = format!("http://{address}/oauth/token");
        let resource_metadata = json!({
            "resource": format!("http://{address}/mcp/"),
            "authorization_servers": [issuer],
            "scopes_supported": ["openid", " email "],
        });
        let authorization_metadata = json!({
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": token_endpoint,
        });
        let app = Router::new()
            .route(
                "/.well-known/oauth-protected-resource/mcp/",
                get({
                    move || {
                        let resource_metadata = resource_metadata.clone();
                        async move { Json(resource_metadata) }
                    }
                }),
            )
            .route(
                "/.well-known/oauth-authorization-server/issuer",
                get({
                    move || {
                        let authorization_metadata = authorization_metadata.clone();
                        async move { Json(authorization_metadata) }
                    }
                }),
            );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server should run");
        });

        TestServer {
            url: format!("http://{address}/mcp/"),
            handle,
        }
    }

    #[tokio::test]
    async fn discovers_metadata_from_protected_resource_path_with_trailing_slash() {
        let server = spawn_protected_resource_discovery_server().await;
        let base_url = Url::parse(&server.url).expect("server URL should parse");
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client should build");

        let discovery = discover_protected_resource_oauth_metadata(&client, &base_url)
            .await
            .expect("oauth metadata should be detected");
        let origin = server.url.trim_end_matches("/mcp/");

        assert_eq!(
            discovery.authorization_metadata.authorization_endpoint,
            format!("{origin}/oauth/authorize")
        );
        assert_eq!(
            discovery.authorization_metadata.token_endpoint,
            format!("{origin}/oauth/token")
        );
        assert_eq!(
            discovery.scopes_supported,
            Some(vec!["openid".to_string(), " email ".to_string()])
        );
    }
}
