import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { AzureManagedIdentityValidate } from '../AzureManagedIdentityValidate/AzureManagedIdentityValidate.node';

function encodeJwtPayload(claims: Record<string, unknown>): string {
	const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
	const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
	const signature = 'fake-signature';
	return `${header}.${payload}.${signature}`;
}

function mockTokenResponse(token: string, expiresOn: number) {
	return {
		ok: true,
		status: 200,
		json: () => Promise.resolve({ access_token: token, expires_on: String(expiresOn) }),
		text: () => Promise.resolve(''),
	} as unknown as Response;
}

const sampleClaims = {
	aud: 'https://storage.azure.com/',
	iss: 'https://sts.windows.net/tenant-123/',
	iat: 1700000000,
	nbf: 1700000000,
	exp: 1700003600,
	sub: 'sub-abc',
	oid: 'oid-456',
	tid: 'tenant-123',
	appid: 'app-789',
	idtyp: 'app',
	ver: '1.0',
	xms_mirid:
		'/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1',
};

function makeExecuteContext(overrides?: {
	resource?: string;
	clientId?: string;
	includeToken?: boolean;
}) {
	const resource = overrides?.resource ?? 'https://storage.azure.com/';
	const clientId = overrides?.clientId ?? '';
	const includeToken = overrides?.includeToken ?? false;

	return {
		getCredentials: vi.fn().mockResolvedValue({ resource, clientId }),
		getNodeParameter: vi
			.fn()
			.mockImplementation((name: string, _index: number, fallback: unknown) => {
				if (name === 'includeToken') return includeToken;
				return fallback;
			}),
		getNode: vi.fn().mockReturnValue({ name: 'Azure MI Validate' }),
		helpers: {
			returnJsonArray: (data: unknown) => [{ json: data }],
		},
	};
}

describe('AzureManagedIdentityValidate', () => {
	const node = new AzureManagedIdentityValidate();
	const savedEnv = { ...process.env };

	beforeEach(() => {
		process.env = { ...savedEnv };
		process.env.IDENTITY_ENDPOINT = 'http://localhost:42356/msi/token';
		process.env.IDENTITY_HEADER = 'test-header';
		vi.restoreAllMocks();
	});

	afterEach(() => {
		process.env = savedEnv;
	});

	it('returns decoded JWT claims without the raw token', async () => {
		const token = encodeJwtPayload(sampleClaims);
		const expiresOn = Math.floor(Date.now() / 1000) + 3600;
		vi.spyOn(global, 'fetch').mockResolvedValue(mockTokenResponse(token, expiresOn));

		const ctx = makeExecuteContext();
		const result = await node.execute.call(ctx as never);

		const output = result[0][0].json as Record<string, unknown>;
		expect(output.success).toBe(true);
		expect(output.audience).toBe('https://storage.azure.com/');
		expect(output.tenantId).toBe('tenant-123');
		expect(output.objectId).toBe('oid-456');
		expect(output.appId).toBe('app-789');
		expect(output.subject).toBe('sub-abc');
		expect(output.identityType).toBe('app');
		expect(output.tokenVersion).toBe('1.0');
		expect(output.issuer).toBe('https://sts.windows.net/tenant-123/');
		expect(output.managedIdentityResourceId).toContain('mi-1');
		expect(output.issuedAt).toBe('2023-11-14T22:13:20.000Z');
		expect(output.expiresAt).toBe('2023-11-14T23:13:20.000Z');

		expect(JSON.stringify(output)).not.toContain(token);
	});

	it('throws when credential resource is empty', async () => {
		const ctx = makeExecuteContext({ resource: '' });

		await expect(node.execute.call(ctx as never)).rejects.toThrow('"Resource / Audience"');
	});

	it('throws a descriptive error when token fetch fails', async () => {
		vi.spyOn(global, 'fetch').mockResolvedValue({
			ok: false,
			status: 403,
			text: () => Promise.resolve('Forbidden'),
			json: () => Promise.resolve({}),
		} as unknown as Response);

		const ctx = makeExecuteContext();

		await expect(node.execute.call(ctx as never)).rejects.toThrow(
			'Failed to acquire or decode managed identity token',
		);
	});

	it('throws when token is not a valid JWT', async () => {
		const expiresOn = Math.floor(Date.now() / 1000) + 3600;
		vi.spyOn(global, 'fetch').mockResolvedValue(mockTokenResponse('not-a-jwt', expiresOn));

		const ctx = makeExecuteContext({ resource: 'api://bad-jwt-test' });

		await expect(node.execute.call(ctx as never)).rejects.toThrow(
			'Failed to acquire or decode managed identity token',
		);
	});

	it('includes the raw token when includeToken is true', async () => {
		const token = encodeJwtPayload(sampleClaims);
		const expiresOn = Math.floor(Date.now() / 1000) + 3600;
		vi.spyOn(global, 'fetch').mockResolvedValue(mockTokenResponse(token, expiresOn));

		const ctx = makeExecuteContext({ includeToken: true });
		const result = await node.execute.call(ctx as never);

		const output = result[0][0].json as Record<string, unknown>;
		expect(output.accessToken).toBe(token);
	});

	it('omits the raw token when includeToken is false', async () => {
		const token = encodeJwtPayload(sampleClaims);
		const expiresOn = Math.floor(Date.now() / 1000) + 3600;
		vi.spyOn(global, 'fetch').mockResolvedValue(mockTokenResponse(token, expiresOn));

		const ctx = makeExecuteContext({ includeToken: false });
		const result = await node.execute.call(ctx as never);

		const output = result[0][0].json as Record<string, unknown>;
		expect(output.accessToken).toBeUndefined();
		expect(JSON.stringify(output)).not.toContain(token);
	});

	it('includes undefined for optional claims not present in the token', async () => {
		const minimalClaims = { aud: 'api://minimal', exp: 1700003600 };
		const token = encodeJwtPayload(minimalClaims);
		const expiresOn = Math.floor(Date.now() / 1000) + 3600;
		vi.spyOn(global, 'fetch').mockResolvedValue(mockTokenResponse(token, expiresOn));

		const ctx = makeExecuteContext({ resource: 'api://minimal' });
		const result = await node.execute.call(ctx as never);

		const output = result[0][0].json as Record<string, unknown>;
		expect(output.success).toBe(true);
		expect(output.audience).toBe('api://minimal');
		expect(output.tenantId).toBeUndefined();
		expect(output.managedIdentityResourceId).toBeUndefined();
	});
});
