import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { ApplicationError, NodeOperationError } from 'n8n-workflow';

import { fetchToken } from '../../credentials/AzureManagedIdentityApi.credentials';

interface JwtClaims {
	aud?: string;
	iss?: string;
	iat?: number;
	nbf?: number;
	exp?: number;
	sub?: string;
	oid?: string;
	tid?: string;
	appid?: string;
	idtyp?: string;
	ver?: string;
	xms_mirid?: string;
}

function decodeJwtPayload(token: string): JwtClaims {
	const parts = token.split('.');
	if (parts.length !== 3) {
		throw new ApplicationError('Token is not a valid JWT (expected 3 segments)');
	}
	return JSON.parse(Buffer.from(parts[1], 'base64url').toString()) as JwtClaims;
}

function epochToIso(epoch: number | undefined): string | undefined {
	if (epoch === undefined) return undefined;
	return new Date(epoch * 1000).toISOString();
}

export class AzureManagedIdentityValidate implements INodeType {
	usableAsTool = true;

	description: INodeTypeDescription = {
		displayName: 'Azure Managed Identity Validate',
		name: 'azureManagedIdentityValidate',
		icon: 'file:../../assets/icons/azure-managed-identity.svg',
		group: ['output'],
		version: 1,
		subtitle: 'Validate Managed Identity',
		description:
			'Acquires a managed identity token and returns its JWT claims without exposing the token itself',
		defaults: {
			name: 'Azure MI Validate',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'azureManagedIdentityApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Include Access Token',
				name: 'includeToken',
				type: 'boolean',
				default: false,
				description:
					'Whether to include the raw Bearer token in the output so it can be used in other nodes (e.g. as a custom header)',
			},
			{
				displayName:
					'Caution: The access token will appear in the node output, execution logs, and the n8n database. Treat it as a secret — do not log, share, or expose it outside trusted workflows.',
				name: 'tokenWarning',
				type: 'notice',
				default: '',
				displayOptions: {
					show: {
						includeToken: [true],
					},
				},
			},
		],
		usableAsTool: true,
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const credentials = await this.getCredentials('azureManagedIdentityApi');
		const resource = credentials.resource as string;
		const clientId = (credentials.clientId as string) || '';

		if (!resource) {
			throw new NodeOperationError(
				this.getNode(),
				'The configured credential is missing "Resource / Audience".',
			);
		}

		const includeToken = this.getNodeParameter('includeToken', 0, false) as boolean;

		let token: string;
		let claims: JwtClaims;
		try {
			token = await fetchToken(resource, clientId);
			claims = decodeJwtPayload(token);
		} catch (error) {
			throw new NodeOperationError(
				this.getNode(),
				`Failed to acquire or decode managed identity token: ${(error as Error).message}`,
			);
		}

		const result: IDataObject = {
			success: true,
			audience: claims.aud,
			issuer: claims.iss,
			tenantId: claims.tid,
			objectId: claims.oid,
			appId: claims.appid,
			subject: claims.sub,
			identityType: claims.idtyp,
			tokenVersion: claims.ver,
			issuedAt: epochToIso(claims.iat),
			notBefore: epochToIso(claims.nbf),
			expiresAt: epochToIso(claims.exp),
			managedIdentityResourceId: claims.xms_mirid,
		};

		if (includeToken) {
			result.accessToken = token;
		}

		return [this.helpers.returnJsonArray(result)];
	}
}
