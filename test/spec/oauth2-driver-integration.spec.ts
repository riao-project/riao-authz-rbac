import {
	ApiRequest, BaseApiEndpoint, BaseApiRouter, BearerAuthenticationScheme,
	RestServer,
} from 'api-machine';
import { LogInterface } from 'api-machine/log';
import { Principal } from '@riao/iam/auth';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';
import {
	OAuth2ClientCredentialsAuthentication,
	OAuth2ClientCredentialsMigrations,
} from '@riao/authn-oauth2-client-cred';
import { AuthzRbacMigrations, RbacAuthorization } from '../../src';
import { createDatabase, runMigrations } from '../database';

describe('Real OAuth2 driver and RBAC HTTP integration', () => {
	const db = createDatabase('oauth2-driver-integration-test');
	const secret = 'real-oauth2-driver-test-secret-at-least-32-characters';
	const clientSecret = 'real-oauth2-client-secret-at-least-32-characters';
	let oauth2: OAuth2ClientCredentialsAuthentication<Principal>;
	let authz: RbacAuthorization;
	let server: RestServer;
	let url: string;
	let token: string;
	let principalId: string;
	let handled: number;

	class Endpoint extends BaseApiEndpoint {
		override path = '/documents';
		override authorization = { action: 'read', resource: 'documents' };
		async handle(request: ApiRequest) {
			handled++;
			return { principalId: request.principal?.id };
		}
	}

	class Router extends BaseApiRouter {
		async routes() {
			return [Endpoint];
		}
	}

	class Server extends RestServer {
		override router = Router;
		get url(): string {
			const address = this.listener.address();
			if (!address || typeof address === 'string') {
				throw new Error('Expected TCP listener');
			}
			return `http://127.0.0.1:${address.port}`;
		}
	}

	beforeAll(async () => {
		await db.init();
		await runMigrations(db, new AuthMigrations());
		await runMigrations(db, new OAuth2ClientCredentialsMigrations());
		await runMigrations(db, new AuthzRbacMigrations());
		oauth2 = new (class extends
			OAuth2ClientCredentialsAuthentication<Principal> {})({
			db, jwtSecret: secret,
		});
		authz = new RbacAuthorization({ db });
		principalId = String(await oauth2.createPrincipal({
			login: 'service', name: 'Service', type: 'service',
		}));
		await oauth2.createClientCredential({
			principalId, clientId: 'client', clientSecret,
		});
		token = (await oauth2.exchangeCredentials('client', clientSecret))
			.access_token;
	});

	beforeEach(async () => {
		handled = 0;
		const instance = new Server({
			port: 0, requireAuthentication: true, authorizer: authz,
			log: jasmine.createSpyObj<LogInterface>(
				'log', ['fatal', 'error', 'warn', 'info', 'debug']
			),
			authentication: new BearerAuthenticationScheme({
				checkToken: async (accessToken) => {
					const payload = await oauth2.verifyAccessToken(accessToken);
					if (!payload) {
						return false;
					}
					return (await oauth2.findActivePrincipal({
						where: { id: payload.principal_id },
					})) ?? false;
				},
			}),
		});
		server = instance;
		await server.start();
		url = instance.url;
	});

	afterEach(async () => {
		await server.stop();
	});

	afterAll(async () => {
		await db.disconnect();
	});

	async function request(accessToken: string) {
		return fetch(`${url}/documents`, {
			headers: { Authorization: `Bearer ${accessToken}` },
		});
	}

	it('enforces access using a real issued token', async () => {
		expect((await request(token)).status).toBe(403);
		expect(handled).toBe(0);
		await authz.grantPermission({
			principalId, action: 'read', resource: 'documents',
		});
		const response = await request(token);
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ principalId });
		expect(handled).toBe(1);
		await authz.revokePermission({ principalId, action: 'read' });
	});

	it('rejects invalid, revoked, and inactive identities', async () => {
		expect((await request('invalid')).status).toBe(401);
		await oauth2.deactivatePrincipal(principalId);
		expect((await request(token)).status).toBe(401);
		await oauth2.principalRepo.update({
			set: { deactivate_timestamp: null }, where: { id: principalId },
		});
		await oauth2.revokeAllCredentials(principalId);
		expect((await request(token)).status).toBe(401);
		await oauth2.credentialsRepo.update({
			set: { deactivate_timestamp: null }, where: { client_id: 'client' },
		});
		expect(handled).toBe(0);
	});

	it('propagates real lookup failures without leaking details', async () => {
		spyOn(oauth2.credentialsRepo, 'findOne').and.rejectWith(
			new Error('Private database failure')
		);
		const response = await request(token);
		expect(response.status).toBe(500);
		expect(await response.text()).not.toContain('Private database failure');
		expect(handled).toBe(0);
	});
});
