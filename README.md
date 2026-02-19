# n8n-nodes-azure-managed-identity

n8n community node that provides an **Azure Managed Identity** credential type and a validation node.

Enables any HTTP Request node to authenticate using Azure Managed Identity tokens — no secrets, no client certificates, no env var access needed from within n8n.

## Included Node

### Azure Managed Identity Validate

A utility node that acquires a managed identity token and returns the decoded JWT claims **without exposing the token itself**. Use it to verify that your managed identity is configured correctly.

Output fields:

| Field                     | Description                                                            |
| ------------------------- | ---------------------------------------------------------------------- |
| success                   | `true` if a token was acquired and decoded                             |
| audience                  | The `aud` claim — resource the token is for                            |
| issuer                    | The `iss` claim — token issuer URL                                     |
| tenantId                  | The `tid` claim — Azure AD tenant ID                                   |
| objectId                  | The `oid` claim — identity object ID                                   |
| appId                     | The `appid` claim — application / client ID                            |
| subject                   | The `sub` claim                                                        |
| identityType              | The `idtyp` claim (e.g. `app`)                                         |
| tokenVersion              | The `ver` claim                                                        |
| issuedAt                  | Token issue time (ISO 8601)                                            |
| notBefore                 | Token validity start (ISO 8601)                                        |
| expiresAt                 | Token expiry time (ISO 8601)                                           |
| managedIdentityResourceId | The `xms_mirid` claim (user-assigned MI resource ID)                   |
| accessToken               | The raw Bearer token (**only when "Include Access Token" is enabled**) |

### Include Access Token option

The node has an **Include Access Token** toggle (off by default). When enabled, the raw Bearer token is added to the output as `accessToken`. This is useful when you need to pass the token to other nodes as a custom header.

> **Caution**: Enabling this option will expose the access token in the node output, execution logs, and the n8n database. Treat it as a secret — do not log, share, or expose it outside trusted workflows.

## Supported Environments

Works on any Azure compute with a managed identity assigned:

- Azure Container Apps
- Azure App Service / Functions
- Azure Kubernetes Service (Workload Identity)
- Azure VMs / VMSS

## Credential Fields

| Field               | Description                                               | Required |
| ------------------- | --------------------------------------------------------- | -------- |
| Resource / Audience | The `api://` URI or resource URL to request a token for   | Yes      |
| Client ID           | Managed Identity client ID (for user-assigned identities) | No       |

## Usage

1. Create a new credential of type **Azure Managed Identity API**
2. Enter the target resource (e.g. `api://your-app-id`, `https://storage.azure.com/`)
3. Optionally enter the MI client ID (required for user-assigned identities)
4. In any HTTP Request node, select **Predefined Credential Type** → **Azure Managed Identity API**

The credential automatically fetches and caches tokens, injecting `Authorization: Bearer <token>` into each request.

## How It Works

When an HTTP Request node fires, the credential's `authenticate` method runs before the request is sent:

1. **Detect the endpoint** — checks for `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` environment variables. If both are present (Container Apps, App Service, AKS), the App Service token endpoint is used. If not, the credential falls back to the VM Instance Metadata Service (IMDS) at `169.254.169.254`.

2. **Check the in-memory cache** — tokens are cached by `resource|clientId`. If a cached token exists and won't expire within the next 5 minutes, it is reused immediately (no network call).

3. **Fetch a new token** — if the cache misses or the token is near expiry, a `GET` request is made to the detected endpoint:

   **App Service / Container Apps / AKS:**

   ```
   GET {IDENTITY_ENDPOINT}?api-version=2019-08-01&resource={resource}[&client_id={clientId}]
   X-IDENTITY-HEADER: {IDENTITY_HEADER}
   ```

   **VMs / VMSS:**

   ```
   GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}[&client_id={clientId}]
   Metadata: true
   ```

   Both calls are local — they talk to a metadata service that Azure provisions on the host and never leave the machine.

4. **Cache and inject** — the returned `access_token` and `expires_on` are stored in memory. The token is added to the outgoing request as `Authorization: Bearer <token>`.

### Token Caching

Tokens are cached **in-process** using a JavaScript `Map`, keyed by `resource|clientId`.

- A token is reused until it is within **5 minutes** of expiry, then a fresh one is fetched.
- The cache is **per-process** — it is not shared across n8n workers or instances. Each n8n worker process maintains its own cache and fetches tokens independently. This is by design: n8n's credential API does not expose a shared cache, and the token endpoint is a local call that never leaves the host, so redundant fetches across workers are negligible.
- Restarting n8n (or an individual worker) clears the cache. The next request triggers a fresh token fetch.
- The cache holds one entry per unique credential configuration. In practice this means a handful of entries, not unbounded growth.

## Disclaimer

> **This software has not been independently security-audited.**
> The author is not a security researcher and assumes no liability for
> vulnerabilities, token leaks, or any other security issues arising from the
> use of this credential type. You are solely responsible for evaluating
> whether it meets your security requirements before deploying to production.

## License

MIT — see [LICENSE](LICENSE)
