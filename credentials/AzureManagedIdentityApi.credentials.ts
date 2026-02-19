import type {
	ICredentialDataDecryptedObject,
	ICredentialType,
	IHttpRequestOptions,
	INodeProperties,
} from 'n8n-workflow';

interface CachedToken {
	accessToken: string;
	expiresOn: number;
}

const TOKEN_REFRESH_MARGIN_S = 300; // refresh 5 min before expiry
const tokenCache = new Map<string, CachedToken>();

function getCacheKey(resource: string, clientId: string): string {
	return `${resource}|${clientId}`;
}

function getCachedToken(resource: string, clientId: string): string | undefined {
	const entry = tokenCache.get(getCacheKey(resource, clientId));
	if (!entry) return undefined;

	const nowS = Math.floor(Date.now() / 1000);
	if (entry.expiresOn - nowS < TOKEN_REFRESH_MARGIN_S) {
		tokenCache.delete(getCacheKey(resource, clientId));
		return undefined;
	}
	return entry.accessToken;
}

const IMDS_ENDPOINT = 'http://169.254.169.254/metadata/identity/oauth2/token';

async function fetchTokenFromAppService(
	resource: string,
	clientId: string,
	identityEndpoint: string,
	identityHeader: string,
): Promise<Response> {
	const params = new URLSearchParams({
		'api-version': '2019-08-01',
		resource,
	});
	if (clientId) params.set('client_id', clientId);

	return fetch(`${identityEndpoint}?${params.toString()}`, {
		method: 'GET',
		headers: { 'X-IDENTITY-HEADER': identityHeader },
	});
}

async function fetchTokenFromImds(resource: string, clientId: string): Promise<Response> {
	const params = new URLSearchParams({
		'api-version': '2018-02-01',
		resource,
	});
	if (clientId) params.set('client_id', clientId);

	return fetch(`${IMDS_ENDPOINT}?${params.toString()}`, {
		method: 'GET',
		headers: { Metadata: 'true' },
	});
}

async function fetchToken(resource: string, clientId: string): Promise<string> {
	const identityEndpoint = process.env.IDENTITY_ENDPOINT;
	const identityHeader = process.env.IDENTITY_HEADER;

	const useAppServiceEndpoint = identityEndpoint && identityHeader;

	const response = useAppServiceEndpoint
		? await fetchTokenFromAppService(resource, clientId, identityEndpoint, identityHeader)
		: await fetchTokenFromImds(resource, clientId);

	if (!response.ok) {
		const body = await response.text();
		const source = useAppServiceEndpoint ? 'App Service/Container Apps' : 'VM IMDS';
		throw new Error(
			`Failed to acquire managed identity token from ${source} (HTTP ${response.status}): ${body}`,
		);
	}

	const data = (await response.json()) as { access_token: string; expires_on: string };
	const expiresOn = parseInt(data.expires_on, 10);

	tokenCache.set(getCacheKey(resource, clientId), {
		accessToken: data.access_token,
		expiresOn,
	});

	return data.access_token;
}

export class AzureManagedIdentityApi implements ICredentialType {
	name = 'azureManagedIdentityApi';

	displayName = 'Azure Managed Identity API';

	icon = 'file:icons/azure-managed-identity.svg' as const;

	documentationUrl =
		'https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview';

	httpRequestNode = {
		name: 'Azure Managed Identity',
		docsUrl:
			'https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview',
		apiBaseUrlPlaceholder: 'https://your-api.example.com/',
	};

	properties: INodeProperties[] = [
		{
			displayName: 'Resource / Audience',
			name: 'resource',
			type: 'string',
			default: '',
			required: true,
			placeholder: 'e.g. api://your-app-id or https://storage.azure.com/',
			description: 'The Azure AD resource URI or audience to request a token for',
		},
		{
			displayName: 'Client ID (User-Assigned MI)',
			name: 'clientId',
			type: 'string',
			default: '',
			description:
				'Client ID of the user-assigned managed identity. Leave empty for system-assigned.',
		},
	];

	authenticate = async (
		credentials: ICredentialDataDecryptedObject,
		requestOptions: IHttpRequestOptions,
	): Promise<IHttpRequestOptions> => {
		const resource = credentials.resource as string;
		const clientId = (credentials.clientId as string) || '';

		if (!resource) {
			throw new Error('Azure Managed Identity credential: "Resource / Audience" is required.');
		}

		const token = getCachedToken(resource, clientId) ?? (await fetchToken(resource, clientId));

		requestOptions.headers = {
			...requestOptions.headers,
			Authorization: `Bearer ${token}`,
		};

		return requestOptions;
	};
}
