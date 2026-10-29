import 'jasmine';
import { Database } from '@riao/dbal';
import { DependencyContainer } from 'hidi';
import { Principal } from '@riao/iam/auth';
import { UnauthorizedError } from 'api-machine';
import { RiaoEndpoint } from '@riao/rest';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';
import {
	DefaultRbacAuthzRouter,
	RbacAuthorization,
	AuthzRbacMigrations,
} from '../../src';
import { createDatabase, runMigrations, runMigrationsDown } from '../database';
import {
	CreateRoleEndpoint,
	GetRolesEndpoint,
	GetRoleEndpoint,
	UpdateRoleEndpoint,
	DeleteRoleEndpoint,
	CreatePermissionEndpoint,
	GetPermissionsEndpoint,
	GetPermissionEndpoint,
	UpdatePermissionEndpoint,
	DeletePermissionEndpoint,
	AddPermissionToRoleEndpoint,
	RemovePermissionFromRoleEndpoint,
	GetRolePermissionsEndpoint,
	AssignRoleToPrincipalEndpoint,
	RemoveRoleFromPrincipalEndpoint,
	GetPrincipalRolesEndpoint,
	EvaluateAuthorizationEndpoint,
	RBAC_AUTHORIZATION_KEY,
} from '../../src/api';

describe('RBAC Authorization API Endpoints', () => {
	let db: Database;
	let auth: RbacAuthorization;
	let createRoleEndpoint: CreateRoleEndpoint;
	let getRolesEndpoint: GetRolesEndpoint;
	let getRoleEndpoint: GetRoleEndpoint;
	let updateRoleEndpoint: UpdateRoleEndpoint;
	let deleteRoleEndpoint: DeleteRoleEndpoint;
	let createPermissionEndpoint: CreatePermissionEndpoint;
	let getPermissionsEndpoint: GetPermissionsEndpoint;
	let getPermissionEndpoint: GetPermissionEndpoint;
	let updatePermissionEndpoint: UpdatePermissionEndpoint;
	let deletePermissionEndpoint: DeletePermissionEndpoint;
	let addPermissionEndpoint: AddPermissionToRoleEndpoint;
	let getRolePermissionsEndpoint: GetRolePermissionsEndpoint;
	let removePermissionEndpoint: RemovePermissionFromRoleEndpoint;
	let assignRoleEndpoint: AssignRoleToPrincipalEndpoint;
	let removeRoleEndpoint: RemoveRoleFromPrincipalEndpoint;
	let getPrincipalRolesEndpoint: GetPrincipalRolesEndpoint;
	let evaluateEndpoint: EvaluateAuthorizationEndpoint;

	beforeAll(async () => {
		db = createDatabase('api-endpoints-test');
		await db.init();

		// Run auth migrations first (RBAC depends on principals)
		const authMigrations = new AuthMigrations();
		await runMigrations(db, authMigrations);

		// Run RBAC migrations
		const rbacMigrations = new AuthzRbacMigrations();
		await runMigrations(db, rbacMigrations);
		await runMigrationsDown(db, rbacMigrations);
		await runMigrations(db, rbacMigrations);

		auth = new RbacAuthorization({
			db,
		});

		const container = new DependencyContainer();
		container.registerInstance(RBAC_AUTHORIZATION_KEY, auth);

		// Initialize endpoints and assign auth dependency
		createRoleEndpoint = new CreateRoleEndpoint();
		createRoleEndpoint.container.setParent(container);
		createRoleEndpoint.inject();

		getRolesEndpoint = new GetRolesEndpoint();
		getRolesEndpoint.container.setParent(container);
		getRolesEndpoint.inject();

		getRoleEndpoint = new GetRoleEndpoint();
		getRoleEndpoint.container.setParent(container);
		getRoleEndpoint.inject();

		updateRoleEndpoint = new UpdateRoleEndpoint();
		updateRoleEndpoint.container.setParent(container);
		updateRoleEndpoint.inject();

		deleteRoleEndpoint = new DeleteRoleEndpoint();
		deleteRoleEndpoint.container.setParent(container);
		deleteRoleEndpoint.inject();

		createPermissionEndpoint = new CreatePermissionEndpoint();
		createPermissionEndpoint.container.setParent(container);
		createPermissionEndpoint.inject();

		getPermissionsEndpoint = new GetPermissionsEndpoint();
		getPermissionsEndpoint.container.setParent(container);
		getPermissionsEndpoint.inject();

		getPermissionEndpoint = new GetPermissionEndpoint();
		getPermissionEndpoint.container.setParent(container);
		getPermissionEndpoint.inject();

		updatePermissionEndpoint = new UpdatePermissionEndpoint();
		updatePermissionEndpoint.container.setParent(container);
		updatePermissionEndpoint.inject();

		deletePermissionEndpoint = new DeletePermissionEndpoint();
		deletePermissionEndpoint.container.setParent(container);
		deletePermissionEndpoint.inject();

		addPermissionEndpoint = new AddPermissionToRoleEndpoint();
		addPermissionEndpoint.container.setParent(container);
		addPermissionEndpoint.inject();

		getRolePermissionsEndpoint = new GetRolePermissionsEndpoint();
		getRolePermissionsEndpoint.container.setParent(container);
		getRolePermissionsEndpoint.inject();

		removePermissionEndpoint = new RemovePermissionFromRoleEndpoint();
		removePermissionEndpoint.container.setParent(container);
		removePermissionEndpoint.inject();

		assignRoleEndpoint = new AssignRoleToPrincipalEndpoint();
		assignRoleEndpoint.container.setParent(container);
		assignRoleEndpoint.inject();

		removeRoleEndpoint = new RemoveRoleFromPrincipalEndpoint();
		removeRoleEndpoint.container.setParent(container);
		removeRoleEndpoint.inject();

		getPrincipalRolesEndpoint = new GetPrincipalRolesEndpoint();
		getPrincipalRolesEndpoint.container.setParent(container);
		getPrincipalRolesEndpoint.inject();

		evaluateEndpoint = new EvaluateAuthorizationEndpoint();
		evaluateEndpoint.container.setParent(container);
		evaluateEndpoint.inject();
	});

	it('injects each CRUD endpoint with its domain repository', () => {
		const groups = [
			{
				repo: auth.rolesRepo,
				endpoints: [
					createRoleEndpoint, getRolesEndpoint, getRoleEndpoint,
					updateRoleEndpoint, deleteRoleEndpoint,
				],
			},
			{
				repo: auth.permissionsRepo,
				endpoints: [
					createPermissionEndpoint, getPermissionsEndpoint,
					getPermissionEndpoint, updatePermissionEndpoint,
					deletePermissionEndpoint,
				],
			},
			{
				repo: auth.rolePermissionsRepo,
				endpoints: [
					addPermissionEndpoint, getRolePermissionsEndpoint,
					removePermissionEndpoint,
				],
			},
			{
				repo: auth.principalRolesRepo,
				endpoints: [
					assignRoleEndpoint, removeRoleEndpoint,
					getPrincipalRolesEndpoint,
				],
			},
		];
		for (const { repo, endpoints } of groups) {
			for (const endpoint of endpoints) {
				expect(endpoint instanceof RiaoEndpoint).toBeTrue();
				expect(endpoint.repo).toBe(repo);
				const parent = new DependencyContainer();
				parent.registerInstance(RBAC_AUTHORIZATION_KEY, auth);
				const unrelatedRepo = {};
				parent.registerInstance('repo', unrelatedRepo);
				endpoint.container = new DependencyContainer();
				endpoint.container.setParent(parent);
				endpoint.inject();
				expect(endpoint.repo).toBe(repo);
				expect(parent.require('repo')).toBe(unrelatedRepo);
			}
		}
		expect(evaluateEndpoint instanceof RiaoEndpoint).toBeFalse();
	});

	it('should cascade the authorization service into the RBAC route tree', async () => {
		const container = new DependencyContainer();
		container.registerInstance(RBAC_AUTHORIZATION_KEY, auth);

		const router = new DefaultRbacAuthzRouter();
		router.container.setParent(container);

		await router.register({ use: () => undefined } as any, '');

		expect(router.registeredRoutes.length).toBe(5);
		for (const childRouter of router.registeredRoutes as any[]) {
			for (const endpoint of childRouter.registeredRoutes as any[]) {
				expect(endpoint.getEffectiveAuthorizationRequirement()).toEqual({
					action: 'manage',
					resource: 'rbac',
				});
			}
		}
	});

	afterAll(async () => {
		await db.disconnect();
	});

	describe('Authorization Evaluation Endpoint', () => {
		it('uses the authenticated request principal, not the body principal', async () => {
			const requestPrincipal: Principal = {
				id: 'authenticated-principal',
				type: 'user',
				login: 'authenticated-user',
				name: 'Authenticated User',
				create_timestamp: new Date(),
			};
			const evaluate = spyOn(auth, 'evaluate').and.resolveTo({
				allowed: true,
			});

			await evaluateEndpoint.handle(
				{
					principal: requestPrincipal,
					body: {
						principalId: 'body-selected-principal',
						action: 'read',
						resource: 'documents',
					},
				} as any
			);

			expect(evaluate).toHaveBeenCalledWith({
				principal: requestPrincipal,
				action: 'read',
				resource: 'documents',
			});
		});

		it('requires an authenticated principal', async () => {
			await expectAsync(
				evaluateEndpoint.handle(
					{ body: {} } as any
				)
			).toBeRejectedWithError(UnauthorizedError);
		});
	});

	describe('Role Endpoints Integration', () => {
		let createdRoleId: string;

		beforeAll(async () => {
			const req = {
				body: {
					roleName: 'test_admin',
					description: 'Test Administrator',
				},
			};

			const res = await createRoleEndpoint.handle(req as any);
			createdRoleId = res.id as string;
		});

		it('should create a role', async () => {
			const req = {
				body: {
					roleName: 'test_admin_2',
					description: 'Test Administrator 2',
				},
			};
			const res = await createRoleEndpoint.handle(req as any);
			expect(res.id).toBeDefined();
		});

		it('should get all roles', async () => {
			const req = {};
			const res = await getRolesEndpoint.handle(req as any);

			expect(Array.isArray(res)).toBeTrue();
			expect(res.length).toBeGreaterThan(0);
			expect(res.find((r: any) => r.name === 'test_admin')).toBeDefined();
		});

		it('should get a specific role', async () => {
			const req = {
				params: { roleId: createdRoleId },
			};
			const res = await getRoleEndpoint.handle(req as any);

			expect(res.id).toBe(createdRoleId);
		});

		it('should update a role', async () => {
			const req = {
				params: { roleId: createdRoleId },
				body: { description: 'Updated Test Administrator' },
			};
			const res = await updateRoleEndpoint.handle(req as any);
		});
	});

	describe('Permission Endpoints Integration', () => {
		let createdPermissionId: string;

		beforeAll(async () => {
			const req = {
				body: {
					action: 'read',
					resource: 'users',
					description: 'Read users',
				},
			};
			const res = await createPermissionEndpoint.handle(req as any);
			createdPermissionId = res.id as string;
		});

		it('should create a permission', async () => {
			const req = {
				body: {
					action: 'write',
					resource: 'users',
					description: 'Write users',
				},
			};
			const res = await createPermissionEndpoint.handle(req as any);

			expect(res.id).toBeDefined();
		});

		it('should get all permissions', async () => {
			const req = {};
			const res = await getPermissionsEndpoint.handle(req as any);

			expect(Array.isArray(res)).toBeTrue();
			expect(res.length).toBeGreaterThan(0);
			expect(
				res.find(
					(p: any) => p.action === 'read' && p.resource === 'users'
				)
			).toBeDefined();
		});
	});

	describe('Endpoint error handling', () => {
		it('should throw error when auth is not initialized', async () => {
			const unInitializedEndpoint = new CreateRoleEndpoint();
			const emptyContainer = new DependencyContainer();
			emptyContainer.registerInstance('repo', {} as any);
			unInitializedEndpoint.container = emptyContainer;

			try {
				unInitializedEndpoint.inject();
				fail('Expected error');
			}
			catch (error: any) {
				expect(error.message).toContain(
					`Required dependency '${RBAC_AUTHORIZATION_KEY}' not found`
				);
			}
		});
	});
});
