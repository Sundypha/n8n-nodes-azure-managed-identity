import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AzureManagedIdentityApi } from '../AzureManagedIdentityApi.credentials';
import type { IHttpRequestOptions } from 'n8n-workflow';

function mockTokenResponse(token: string, expiresOn: number) {
	return {
		ok: true,
		status: 200,
		json: () => Promise.resolve({ access_token: token, expires_on: String(expiresOn) }),
		text: () => Promise.resolve(''),
	} as unknown as Response;
}

function makeRequestOptions(): IHttpRequestOptions {
	return { url: 'https://example.com', method: 'GET' } as IHttpRequestOptions;
}

describe('AzureManagedIdentityApi', () => {
	const credential = new AzureManagedIdentityApi();
	const savedEnv = { ...process.env };

	beforeEach(() => {
		process.env = { ...savedEnv };
		vi.restoreAllMocks();
	});

	afterEach(() => {
		process.env = savedEnv;
	});

	it('throws when resource is empty', async () => {
		process.env.IDENTITY_ENDPOINT = 'http://localhost:42356/msi/token';
		process.env.IDENTITY_HEADER = 'test-header';

		await expect(
			credential.authenticate(
				{ resource: '', clientId: '' },
				makeRequestOptions(),
			),
		).rejects.toThrow('"Resource / Audience" is required');
	});

	describe('App Service / Container Apps endpoint (IDENTITY_ENDPOINT)', () => {
		beforeEach(() => {
			process.env.IDENTITY_ENDPOINT = 'http://localhost:42356/msi/token';
			process.env.IDENTITY_HEADER = 'test-header';
		});

		it('fetches a token using X-IDENTITY-HEADER and sets Authorization', async () => {
			const expiresOn = Math.floor(Date.now() / 1000) + 3600;
			const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValue(
				mockTokenResponse('appservice-token', expiresOn),
			);

			const result = await credential.authenticate(
				{ resource: 'api://test-appservice', clientId: '' },
				makeRequestOptions(),
			);

			expect(fetchSpy).toHaveBeenCalledOnce();
			const calledUrl = fetchSpy.mock.calls[0][0] as string;
			expect(calledUrl).toContain('http://localhost:42356/msi/token');
			expect(calledUrl).toContain('api-version=2019-08-01');

			const calledHeaders = fetchSpy.mock.calls[0][1]?.headers as Record<string, string>;
			expect(calledHeaders['X-IDENTITY-HEADER']).toBe('test-header');

			expect(result.headers).toEqual(
				expect.objectContaining({ Authorization: 'Bearer appservice-token' }),
			);
		});

		it('caches tokens and reuses them on subsequent calls', async () => {
			const expiresOn = Math.floor(Date.now() / 1000) + 3600;
			const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValue(
				mockTokenResponse('cached-token', expiresOn),
			);

			const creds = { resource: 'api://test-cache-as', clientId: '' };

			await credential.authenticate(creds, makeRequestOptions());
			const result = await credential.authenticate(creds, makeRequestOptions());

			expect(fetchSpy).toHaveBeenCalledOnce();
			expect(result.headers).toEqual(
				expect.objectContaining({ Authorization: 'Bearer cached-token' }),
			);
		});

		it('refreshes token when it is near expiry', async () => {
			const nearExpiry = Math.floor(Date.now() / 1000) + 100;
			const freshExpiry = Math.floor(Date.now() / 1000) + 3600;

			const fetchSpy = vi.spyOn(global, 'fetch')
				.mockResolvedValueOnce(mockTokenResponse('old-token', nearExpiry))
				.mockResolvedValueOnce(mockTokenResponse('new-token', freshExpiry));

			const creds = { resource: 'api://test-refresh-as', clientId: '' };

			await credential.authenticate(creds, makeRequestOptions());
			const result = await credential.authenticate(creds, makeRequestOptions());

			expect(fetchSpy).toHaveBeenCalledTimes(2);
			expect(result.headers).toEqual(
				expect.objectContaining({ Authorization: 'Bearer new-token' }),
			);
		});

		it('throws a meaningful error on non-200 response', async () => {
			vi.spyOn(global, 'fetch').mockResolvedValue({
				ok: false,
				status: 403,
				text: () => Promise.resolve('Forbidden'),
				json: () => Promise.resolve({}),
			} as unknown as Response);

			await expect(
				credential.authenticate(
					{ resource: 'api://test-error-as', clientId: '' },
					makeRequestOptions(),
				),
			).rejects.toThrow('App Service/Container Apps (HTTP 403): Forbidden');
		});
	});

	describe('VM / VMSS endpoint (IMDS at 169.254.169.254)', () => {
		beforeEach(() => {
			delete process.env.IDENTITY_ENDPOINT;
			delete process.env.IDENTITY_HEADER;
		});

		it('falls back to IMDS endpoint with Metadata header', async () => {
			const expiresOn = Math.floor(Date.now() / 1000) + 3600;
			const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValue(
				mockTokenResponse('vm-token', expiresOn),
			);

			const result = await credential.authenticate(
				{ resource: 'api://test-vm', clientId: '' },
				makeRequestOptions(),
			);

			expect(fetchSpy).toHaveBeenCalledOnce();
			const calledUrl = fetchSpy.mock.calls[0][0] as string;
			expect(calledUrl).toContain('169.254.169.254/metadata/identity/oauth2/token');
			expect(calledUrl).toContain('api-version=2018-02-01');

			const calledHeaders = fetchSpy.mock.calls[0][1]?.headers as Record<string, string>;
			expect(calledHeaders['Metadata']).toBe('true');
			expect(calledHeaders['X-IDENTITY-HEADER']).toBeUndefined();

			expect(result.headers).toEqual(
				expect.objectContaining({ Authorization: 'Bearer vm-token' }),
			);
		});

		it('passes client_id for user-assigned identity on VM', async () => {
			const expiresOn = Math.floor(Date.now() / 1000) + 3600;
			const fetchSpy = vi.spyOn(global, 'fetch').mockResolvedValue(
				mockTokenResponse('vm-ua-token', expiresOn),
			);

			await credential.authenticate(
				{ resource: 'api://test-vm-ua', clientId: 'my-client-id' },
				makeRequestOptions(),
			);

			const calledUrl = fetchSpy.mock.calls[0][0] as string;
			expect(calledUrl).toContain('client_id=my-client-id');
		});

		it('throws a meaningful error on non-200 IMDS response', async () => {
			vi.spyOn(global, 'fetch').mockResolvedValue({
				ok: false,
				status: 404,
				text: () => Promise.resolve('Not Found'),
				json: () => Promise.resolve({}),
			} as unknown as Response);

			await expect(
				credential.authenticate(
					{ resource: 'api://test-error-vm', clientId: '' },
					makeRequestOptions(),
				),
			).rejects.toThrow('VM IMDS (HTTP 404): Not Found');
		});
	});
});
