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
		await auth.addPermissionToRole({
			roleId, permissionId,
		});
		await auth.assignRole({
			principalId: admin.id, roleId,
		});
		const secondaryRoleId = await auth.role({ name: 'search-secondary' });
		const secondaryPermissionId = await auth.permission({
			action: 'read', resource: 'search-records',
		});
		await auth.addPermissionToRole({
			roleId: secondaryRoleId, permissionId: secondaryPermissionId,
		});
		await auth.assignRole({
			principalId: admin.id, roleId: secondaryRoleId,
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

	async function request(
		path: string, token?: string, body?: unknown,
		method = body === undefined ? 'GET' : 'POST'
	) {
		return fetch(`${server.url}${path}`, {
			method,
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

	it('lists relationships at their model routes and removes nested routes',
		async () => {
			const role = await auth.rolesRepo.findOne({
				where: { name: 'rbac-manager' },
			});
			if (!role) {
				throw new Error('Expected the RBAC manager role');
			}
			const permissions = await request(
				'/rbac/role-permissions?limit=1&orderBy=id&orderDirection=ASC',
				'admin'
			);
			expect(permissions.status).toBe(200);
			const permissionRecords = await permissions.json() as unknown[];
			expect(permissionRecords.length).toBe(1);
			const roles = await request(
				'/rbac/principal-roles', 'admin'
			);
			expect(roles.status).toBe(200);
			expect(await roles.json()).toEqual(
				jasmine.arrayContaining([
					jasmine.objectContaining({
						principal_id: admin.id, role_id: role.id,
					}),
				])
			);
			for (const path of [
				`/rbac/roles/${role.id}/permissions`,
				`/rbac/principals/${admin.id}/roles`,
			]) {
				expect((await request(path, 'admin')).status).toBe(404);
				expect((await request(path, 'admin', {})).status).toBe(404);
				expect((await request(
					`${path}/${randomUUID()}`, 'admin', undefined, 'DELETE'
				)).status).toBe(404);
			}
		});

	for (const model of ['principal-roles', 'role-permissions']) {
		describe(`${model} assignment lifecycle`, () => {
			const path = `/rbac/${model}`;

			it('creates, searches, removes and recreates an assignment',
				async () => {
					const roleId = await auth.role({
						name: `lifecycle-${randomUUID()}`,
					});
					const action = `lifecycle-${randomUUID()}`;
					const permissionId = await auth.permission({ action });
					if (model === 'principal-roles') {
						await auth.addPermissionToRole({
							roleId, permissionId,
						});
					}
					const body = model === 'principal-roles'
						? { principalId: user.id, roleId }
						: { roleId, permissionId };
					const created = await request(path, 'admin', body);
					expect(created.status).toBe(201);
					const { id } = await created.json() as { id: string };
					expect(typeof id).toBe('string');
					if (model === 'principal-roles') {
						expect((await auth.evaluate({
							principal: user, action,
						})).allowed).toBeTrue();
					}
					const duplicate = await request(path, 'admin', body);
					expect(duplicate.status).toBe(201);
					expect(await duplicate.json()).toEqual({ id });

					const search = await request(`${path}/search`, 'admin', {
						where: [{
							column: 'role_id', operator: '=', value: roleId,
						}],
					});
					expect(search.status).toBe(200);
					expect(await search.json()).toEqual({
						records: [jasmine.objectContaining({
							id, role_id: roleId,
						})],
						count: 1,
					});

					const removed = await request(
						`${path}/${id}`, 'admin', undefined, 'DELETE'
					);
					expect(removed.status).toBe(204);
					if (model === 'principal-roles') {
						const record = await auth.principalRolesRepo.findOne({
							where: { id },
						});
						expect(record?.deactivate_timestamp)
							.toEqual(jasmine.any(Date));
						expect((await auth.evaluate({
							principal: user, action,
						})).allowed).toBeFalse();
					}
					else {
						expect(await auth.rolePermissionsRepo.findOne({
							where: { id },
						})).toBeFalsy();
					}

					const recreated = await request(path, 'admin', body);
					expect(recreated.status).toBe(201);
					const recreatedBody = await recreated.json() as {
						id: string;
					};
					if (model === 'principal-roles') {
						expect(recreatedBody.id).toBe(id);
						expect((await auth.evaluate({
							principal: user, action,
						})).allowed).toBeTrue();
					}
					else {
						expect(recreatedBody.id).not.toBe(id);
					}
					await auth.rolesRepo.delete({ where: { id: roleId } });
					await auth.permissionsRepo.delete({
						where: { id: permissionId },
					});
				});

			it('validates creation and reports missing assignment IDs',
				async () => {
					for (const body of [
						{}, { roleId: randomUUID() },
						{ roleId: {}, principalId: {}, permissionId: {} },
					]) {
						expect((await request(path, 'admin', body)).status)
							.toBe(422);
					}
					expect((await request(
						`${path}/${randomUUID()}`, 'admin', undefined, 'DELETE'
					)).status).toBe(404);
				});

			it('protects creation, listing and removal', async () => {
				for (const token of [undefined, 'user']) {
					const expected = token === undefined ? 401 : 403;
					expect((await request(path, token)).status).toBe(expected);
					expect((await request(path, token, {})).status)
						.toBe(expected);
					expect((await request(
						`${path}/${randomUUID()}`, token, undefined, 'DELETE'
					)).status).toBe(expected);
				}
			});
		});
	}

	const searchModels = [
		{
			path: '/rbac/roles/search',
			columns: [
				'id', 'name', 'description',
				'create_timestamp', 'deactivate_timestamp',
			],
		},
		{
			path: '/rbac/permissions/search',
			columns: [
				'id', 'action', 'resource', 'description', 'create_timestamp',
			],
		},
		{
			path: '/rbac/role-permissions/search',
			columns: ['id', 'role_id', 'permission_id', 'create_timestamp'],
		},
		{
			path: '/rbac/principal-roles/search',
			columns: [
				'id', 'principal_id', 'role_id',
				'create_timestamp', 'deactivate_timestamp',
			],
		},
	];

	for (const { path, columns } of searchModels) {
		describe(path, () => {
			it('requires RBAC administration access', async () => {
				expect((await request(path, undefined, {})).status).toBe(401);
				expect((await request(path, 'user', {})).status).toBe(403);
				expect((await request(path, 'admin', {})).status).toBe(200);
			});

			it('selects, filters, orders and paginates model records',
				async () => {
					const all = await request(path, 'admin', {});
					expect(all.status).toBe(200);
					const result = await all.json() as {
						records: { id: string }[]; count: number;
					};
					expect(result.count).toBeGreaterThan(1);
					expect(Object.keys(result.records[0]).sort())
						.toEqual([...columns].sort());
					const ids = result.records.map(({ id }) => id).sort();
					const ordered = await request(path, 'admin', {
						columns: ['id'],
						order: [{ column: 'id', direction: 'ASC' }],
						limit: 1, offset: 1,
					});
					expect(ordered.status).toBe(200);
					expect(await ordered.json()).toEqual({
						records: [{ id: ids[1] }], count: result.count,
					});
					const descending = await request(path, 'admin', {
						columns: ['id'],
						order: [{ column: 'id', direction: 'DESC' }],
						limit: 1,
					});
					expect(descending.status).toBe(200);
					expect(await descending.json()).toEqual({
						records: [{ id: ids[ids.length - 1] }],
						count: result.count,
					});
					const id = result.records[0].id;
					const body = {
						columns: ['id'],
						where: [{ column: 'id', operator: '=', value: id }],
						order: [{ column: 'id', direction: 'DESC' }],
						limit: 1, offset: 0,
					};
					const filtered = await request(path, 'admin', body);
					expect(filtered.status).toBe(200);
					expect(await filtered.json()).toEqual({
						records: [{ id }], count: 1,
					});
					const page = await request(path, 'admin', {
						...body, offset: 1,
					});
					expect(page.status).toBe(200);
					expect(await page.json()).toEqual({
						records: [], count: 1,
					});
				});

			it('rejects columns outside the model allowlist', async () => {
				for (const body of [
					{ columns: ['unknown_column'] },
					{
						where: [{
							column: 'unknown_column', operator: '=', value: 1,
						}],
					},
					{ order: [{ column: 'unknown_column' }] },
					{ orderBy: 'unknown_column', orderDirection: 'ASC' },
					{
						aggregates: [{
							column: 'unknown_column', function: 'count',
						}],
					},
					{
						aggregates: [{ column: 'id', function: 'count' }],
						groupBy: ['unknown_column'],
					},
				]) {
					expect((await request(path, 'admin', body)).status)
						.toBe(422);
				}
			});
		});
	}

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
