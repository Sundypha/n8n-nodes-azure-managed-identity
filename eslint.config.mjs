import { configWithoutCloudSupport } from '@n8n/node-cli/eslint';

export default [
	...configWithoutCloudSupport,
	{
		ignores: ['credentials/__tests__/**'],
	},
	{
		files: ['credentials/**/*.ts'],
		rules: {
			'@n8n/community-nodes/credential-test-required': 'off',
		},
	},
	{
		files: ['package.json'],
		rules: {
			'n8n-nodes-base/community-package-json-n8n-nodes-empty': 'off',
		},
	},
];
