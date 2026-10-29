import 'jasmine';
import {
	ApiRequest,
	BadRequestError,
	BaseApiEndpoint,
	BaseApiRouter,
	BearerAuthenticationScheme,
	RestServer,
} from 'api-machine';
import { LogInterface } from 'api-machine/log';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';
import { Principal } from '@riao/iam/auth';
import { Database } from '@riao/dbal';
import { randomUUID } from 'crypto';
import {
	AuthzRbacMigrations,
	DefaultRbacAuthzRouter,
	EvaluateAuthorizationEndpoint,
	RbacAuthorization,
} from '../../src';
import { createDatabase, runMigrations } from '../database';

describe('OAuth2 and RBAC HTTP enforcement', () => {
	let db: Database;
	let auth: RbacAuthorization;
	let logger: jasmine.SpyObj<LogInterface>;
	let handled: number;
	let admin: Principal;
	let user: Principal;

	class PublicEndpoint extends BaseApiEndpoint {
		override path = '/health';
		override authentication = null;
		override authorization = null;

		async handle() {
			return { healthy: true };
		}
	}

	class ProbeEndpoint extends BaseApiEndpoint {
		override path = '/probe';
		override authorization = { action: 'manage', resource: 'rbac' };

		async handle(request: ApiRequest) {
			handled++;
			return { principalId: request.principal?.id };
		}
	}

	class Router extends BaseApiRouter {
		async routes() {
			return [DefaultRbacAuthzRouter, ProbeEndpoint, PublicEndpoint];
		}
	}

	class TestServer extends RestServer {
		override router = Router;

		constructor() {
			super({
				port: 0,
				log: logger,
				requireAuthentication: true,
				authorizer: auth,
				authentication: new BearerAuthenticationScheme({
					checkToken: async (token: string) => {
						if (token === 'backend-error') {
							throw new Error('Token service unavailable');
						}
						return token === 'admin' ? admin :
							token === 'user' ? user : false;
					},
				}),
			});
		}

		get url(): string {
			const address = this.listener.address();
			if (!address || typeof address === 'string') {
				throw new Error('Expected a TCP listener');
			}
			return `http://127.0.0.1:${address.port}`;
		}
	}

	let server: TestServer;

	beforeAll(async () => {
		db = createDatabase('security-integration-test');
		await db.init();
		await runMigrations(db, new AuthMigrations());
		await runMigrations(db, new AuthzRbacMigrations());
		const principals = db.getQueryRepository<Principal>({
			table: 'iam_principals', identifiedBy: 'id',
		});
		admin = {
			id: randomUUID(), type: 'user', login: 'admin', name: 'Admin',
			create_timestamp: new Date(),
		};
		user = {
			id: randomUUID(), type: 'user', login: 'user', name: 'User',
			create_timestamp: new Date(),
		};
		await principals.insert({ records: [admin, user] });
		auth = new RbacAuthorization({ db });
		const roleId = await auth.role({ name: 'rbac-manager' });
		const permissionId = await auth.permission({
			action: 'manage', resource: 'rbac',
		});
		await auth.addPermissionToRole({ roleId, permissionId });
		await auth.assignRole({
			principalId: admin.id, roleId,
		});
	});

	afterAll(async () => {
		await db.disconnect();
	});

	beforeEach(async () => {
		handled = 0;
		logger = jasmine.createSpyObj<LogInterface>(
			'logger', ['fatal', 'error', 'warn', 'info', 'debug']
		);
		server = new TestServer();
		await server.start();
	});

	afterEach(async () => {
		await server.stop();
	});

	async function request(path: string, token?: string, body?: unknown) {
		return fetch(`${server.url}${path}`, {
			method: body === undefined ? 'GET' : 'POST',
			headers: {
				...(token ? { Authorization: `Bearer ${token}` } : {}),
				'Content-Type': 'application/json',
				'x-request-id': 'rbac-test',
			},
			body: body === undefined ? undefined : JSON.stringify(body),
		});
	}

	it('protects the default administration routes', async () => {
		expect((await request('/rbac/roles')).status).toBe(401);
		expect((await request('/rbac/roles', 'user')).status).toBe(403);
		expect((await request('/rbac/roles', 'admin')).status).toBe(200);
	});

	it('prevents rejected requests from executing protected handlers',
		async () => {
			for (const token of [undefined, 'invalid', 'inactive', 'user']) {
				const response = await request('/probe', token);
				expect(response.status).toBe(token === 'user' ? 403 : 401);
			}
			expect(handled).toBe(0);
			const allowed = await request('/probe', 'admin');
			expect(allowed.status).toBe(200);
			expect(await allowed.json()).toEqual({ principalId: admin.id });
			expect(handled).toBe(1);
		});

	it('allows explicit public exceptions', async () => {
		expect((await request('/health')).status).toBe(200);
	});

	it('rejects invalid evaluation inputs with 422', async () => {
		for (const body of [
			{}, { action: 1 }, { action: ' ' }, { action: [] },
			{ action: 'read', resource: {} },
			{ action: 'read', resource: null },
			{ action: 'read', resource: '' },
		]) {
			const response = await request(
				'/rbac/evaluate', 'admin', body
			);
			expect(response.status).toBe(422);
		}
	});

	it('evaluates the authenticated principal rather than the body identity',
		async () => {
			const evaluate = spyOn(auth, 'evaluate').and.callThrough();
			const response = await request('/rbac/evaluate', 'admin', {
				action: 'manage', resource: 'rbac', principalId: user.id,
			});
			expect(response.status).toBe(201);
			expect(await response.json()).toEqual({ allowed: true });
			expect(evaluate).toHaveBeenCalledWith({
				principal: admin, action: 'manage', resource: 'rbac',
			});
		});

	it('fails closed on authentication backend errors', async () => {
		expect((await request('/probe', 'backend-error')).status).toBe(500);
		expect(handled).toBe(0);
	});

	it('propagates real RBAC store failures as 500', async () => {
		const error = new Error('Policy database unavailable');
		spyOn(auth.principalRolesRepo, 'find').and.rejectWith(error);
		const response = await request('/probe', 'admin');
		expect(response.status).toBe(500);
		expect(handled).toBe(0);
		expect(logger.error).toHaveBeenCalledWith(
			'authorization.error', jasmine.objectContaining({ error })
		);
		const body = await response.text();
		expect(body).not.toContain(error.message);
	});

	it('returns a policy denial for a valid evaluation request', async () => {
		const response = await request('/rbac/evaluate', 'admin', {
			action: 'ungranted-action',
		});
		expect(response.status).toBe(201);
		expect(await response.json()).toEqual(jasmine.objectContaining({
			allowed: false,
		}));
	});

	it('returns 500 for evaluation backend failures without exposing details',
		async () => {
			const error = new Error('Evaluation backend unavailable');
			spyOn(auth, 'evaluate').and.callFake(async (context) => {
				if (context.action === 'backend-failure') {
					throw error;
				}
				return { allowed: true };
			});
			const response = await request(
				'/rbac/evaluate',
				'admin',
				{ action: 'backend-failure' }
			);
			expect(response.status).toBe(500);
			expect(logger.error).toHaveBeenCalledWith(
				'rbac.evaluate.error', jasmine.objectContaining({
					error, principalId: admin.id, requestId: 'rbac-test',
				})
			);
			expect(await response.text()).not.toContain(error.message);
		});

	it('preserves typed evaluation errors and logs the original error',
		async () => {
			const error = new BadRequestError('Invalid policy input');
			const evaluate = spyOn(auth, 'evaluate').and.callFake(
				async (context) => {
					if (context.action === 'fail') {
						throw error;
					}
					return { allowed: true };
				}
			);
			const response = await request('/rbac/evaluate', 'admin', {
				action: 'fail',
			});
			expect(response.status).toBe(400);
			expect(evaluate).toHaveBeenCalled();
			expect(logger.error).toHaveBeenCalledWith(
				'rbac.evaluate.error', jasmine.objectContaining({
					error, principalId: admin.id, requestId: 'rbac-test',
				})
			);
		});

	it('rejects missing principals before evaluating access', async () => {
		const endpoint = new EvaluateAuthorizationEndpoint();
		await expectAsync(endpoint.handle({ body: {} } as ApiRequest))
			.toBeRejectedWithError(/authenticated principal/);
	});
});
