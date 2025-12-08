import 'jasmine';
import { Database, QueryRepository } from '@riao/dbal';
import { Principal } from '@riao/iam/auth';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';
import {
	RbacAuthorization,
	RbacRole,
	AuthzRbacMigrations,
	RbacRolePermission,
	RbacPermission,
	RbacPrincipalRole,
} from '../../src';
import { createDatabase, runMigrations, runMigrationsDown } from '../database';

describe('RBAC Authorization', () => {
	let db: Database;
	let rbacMigrations: AuthzRbacMigrations;
	let rbac: RbacAuthorization;
	let testPrincipalId: string;
	let testPrincipal: Principal;

	let rolesRepo: QueryRepository<RbacRole>;
	let permissionsRepo: QueryRepository<RbacPermission>;
	let rolePermissionsRepo: QueryRepository<RbacRolePermission>;
	let principalRolesRepo: QueryRepository<RbacPrincipalRole>;

	beforeAll(async () => {
		db = createDatabase('rbac-test');
		rbacMigrations = new AuthzRbacMigrations();

		await db.init();

		// Run auth migrations first (RBAC depends on principals)
		const authMigrations = new AuthMigrations();
		await runMigrations(db, authMigrations);

		// Run RBAC migrations
		await runMigrations(db, rbacMigrations);
		await runMigrationsDown(db, rbacMigrations);
		await runMigrations(db, rbacMigrations);

		rbac = new RbacAuthorization({ db });

		rolesRepo = rbac.rolesRepo;
		permissionsRepo = rbac.permissionsRepo;
		rolePermissionsRepo = rbac.rolePermissionsRepo;
		principalRolesRepo = rbac.principalRolesRepo;
	});

	beforeEach(async () => {
		// Create a test principal for each test
		const inserted = await db
			.getQueryRepository({
				table: 'iam_principals',
				identifiedBy: 'id',
			})
			.insertOne({
				record: {
					login: 'test_user_' + Date.now(),
					name: 'Test User',
					type: 'user',
					create_timestamp: new Date(),
				} as unknown as Principal,
			});
		testPrincipalId = (inserted as unknown as { id: string }).id;

		// Fetch the full principal object
		testPrincipal = (await db
			.getQueryRepository<Principal>({
				table: 'iam_principals',
				identifiedBy: 'id',
			})
			.findOne({
				where: { id: testPrincipalId },
			})) as Principal;
	});

	describe('evaluate()', () => {
		it('should deny access when principal has no roles', async () => {
			const result = await rbac.evaluate({
				principal: testPrincipal,
				action: 'read',
				resource: 'documents',
			});

			expect(result.allowed).toBe(false);
			expect(result.reason).toContain('no active roles');
		});

		it('should deny access when no permission exists', async () => {
			// Create and assign a role but no permission
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'viewer_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			const result = await rbac.evaluate({
				principal: testPrincipal,
				action: 'delete',
				resource: 'documents',
			});

			expect(result.allowed).toBe(false);
		});

		it('should allow access with required permission', async () => {
			const action = 'read_' + Date.now();
			const resource = 'document_' + Date.now();

			// Create permission
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource,
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create role
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'editor_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign permission to role
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			const result = await rbac.evaluate({
				principal: testPrincipal,
				action,
				resource,
			});

			expect(result.allowed).toBe(true);
		});

		it('should handle errors gracefully', async () => {
			const result = await rbac.evaluate({
				principal: {
					id: 'invalid-id',
					login: 'test',
					name: 'Test',
					type: 'user',
					create_timestamp: new Date(),
				},
				action: 'read',
			});

			expect(result.allowed).toBe(false);
			expect(result.reason).toBeDefined();
		});

		it('denies access without resource', async () => {
			const action = 'write_' + Date.now();
			const resource = 'specific_' + Date.now();

			// Create permission with specific resource
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource,
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create role
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'editor_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign permission to role
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			// Evaluate without resource should deny
			const result = await rbac.evaluate({
				principal: testPrincipal,
				action,
			});

			expect(result.allowed).toBe(false);
		});

		it('should allow access with action-only permission', async () => {
			const action = 'generic_' + Date.now();

			// Create permission with null resource
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource: null,
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create role
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'generic_role_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign permission to role
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			// Should allow with any resource
			const result = await rbac.evaluate({
				principal: testPrincipal,
				action,
				resource: 'any_resource',
			});

			expect(result.allowed).toBe(true);
		});

		it('denies access when principal role is deactivated', async () => {
			const action = 'deactivated_' + Date.now();
			const resource = 'data_' + Date.now();

			// Create permission
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource,
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create role
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: action,
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign permission to role
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal with deactivate_timestamp
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
					deactivate_timestamp: new Date(),
				},
			});

			// Should deny access since role is deactivated
			const result = await rbac.evaluate({
				principal: testPrincipal,
				action,
				resource,
			});

			expect(result.allowed).toBe(false);
		});
	});

	describe('isAuthorized()', () => {
		it('should return false when no roles', async () => {
			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action: 'read',
			});

			expect(authorized).toBe(false);
		});

		it('should return true with permission', async () => {
			const action = 'write_' + Date.now();

			// Create permission
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource: 'files',
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create role
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'contributor_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign permission to role
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource: 'files',
			});
			expect(authorized).toBe(true);
		});

		it('should return false without matching permission', async () => {
			const action = 'missing_' + Date.now();

			// Create role without permission
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'viewer_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign role to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action: action,
			});

			expect(authorized).toBe(false);
		});
	});

	describe('grantPermission()', () => {
		it('should create role and assign to principal', async () => {
			const action = 'admin_' + Date.now();

			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
			});

			// Verify role was created
			const role = await rolesRepo.findOne({
				where: { name: action },
			});

			expect(role).toBeDefined();
			expect(role?.name).toBe(action);

			// Verify assignment was created
			const assignment = await principalRolesRepo.findOne({
				where: {
					principal_id: testPrincipalId,
					role_id: role?.id,
				},
			});

			expect(assignment).toBeDefined();
		});

		it('should reuse existing role', async () => {
			const action = 'existing_' + Date.now();

			// Create role first
			await rolesRepo.insertOne({
				record: {
					name: action,
					create_timestamp: new Date(),
				},
			});

			// Grant permission using existing role
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
			});

			// Verify only one role
			const roles = await rolesRepo.find({
				where: { name: action },
			});

			expect((roles ?? []).length).toBe(1);
		});

		it('should handle duplicate assignments', async () => {
			const action = 'dup_' + Date.now();

			// Grant twice
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
			});
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
			});

			// Should succeed without error
			expect(true).toBe(true);
		});

		it('should create multiple roles for different actions', async () => {
			const action1 = 'action1_' + Date.now();
			const action2 = 'action2_' + Date.now();

			// Grant two different permissions
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action: action1,
			});
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action: action2,
			});

			// Verify both roles exist
			const roles = await rolesRepo.find({});

			const roleNames = (roles ?? []).map((r) => r.name);
			expect(roleNames).toContain(action1);
			expect(roleNames).toContain(action2);
		});

		it('restores assignment granting revoked permission', async () => {
			const action = 'restore_' + Date.now();

			// Grant permission
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
			});

			// Revoke it
			await rbac.revokePermission({
				principalId: testPrincipalId,
				action,
			});

			// Grant again
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
			});

			// Should have active assignment
			const role = await rolesRepo.findOne({
				where: { name: action },
			});

			const activeAssignment = await principalRolesRepo.findOne({
				where: {
					principal_id: testPrincipalId,
					role_id: role?.id,
					deactivate_timestamp: null,
				},
			});

			expect(activeAssignment).toBeDefined();
		});
	});

	describe('revokePermission()', () => {
		it('should deactivate role assignment', async () => {
			const action = 'revoke_' + Date.now();

			// Grant permission
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
			});

			// Revoke permission
			await rbac.revokePermission({
				principalId: testPrincipalId,
				action,
			});

			// Verify assignment was deactivated
			const role = await rolesRepo.findOne({
				where: { name: action },
			});

			const assignment = await principalRolesRepo.findOne({
				where: {
					principal_id: testPrincipalId,
					role_id: role?.id,
				},
			});

			expect(assignment?.['deactivate_timestamp']).not.toBeNull();
		});

		it('should handle non-existent role', async () => {
			// Should not throw
			await rbac.revokePermission({
				principalId: testPrincipalId,
				action: 'nonexistent',
			});
			expect(true).toBe(true);
		});

		it('should prevent access after revocation', async () => {
			const action = 'revoked_' + Date.now();
			const resource = 'data_' + Date.now();

			// Create permission
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource,
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create role
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: action,
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign permission to role
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
			});

			// Verify access before revocation
			let authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource,
			});
			expect(authorized).toBe(true);

			// Revoke permission
			await rbac.revokePermission({
				principalId: testPrincipalId,
				action,
			});

			// Verify access after revocation
			authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource,
			});
			expect(authorized).toBe(false);
		});

		it('is idempotent revoking already revoked permission', async () => {
			const action = 'idempotent_' + Date.now();

			// Grant permission
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
			});

			// Revoke twice
			await rbac.revokePermission({
				principalId: testPrincipalId,
				action,
			});
			await rbac.revokePermission({
				principalId: testPrincipalId,
				action,
			});

			// Should not throw and permission should be revoked
			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action: action,
			});
			expect(authorized).toBe(false);
		});

		it('should only deactivate specific role assignment', async () => {
			const action1 = 'role1_' + Date.now();
			const action2 = 'role2_' + Date.now();

			// Grant two permissions to principal
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action: action1,
			});
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action: action2,
			});

			// Revoke only first permission
			await rbac.revokePermission({
				principalId: testPrincipalId,
				action: action1,
			});

			// First should be denied
			let authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action: action1,
			});
			expect(authorized).toBe(false);

			// Second should be allowed
			authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action: action2,
			});
			expect(authorized).toBe(true);
		});
	});

	describe('Multiple Roles', () => {
		it('should allow if any role has permission', async () => {
			const action = 'multi_' + Date.now();
			const resource = 'shared_' + Date.now();

			// Create permission
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource,
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create two roles
			const role1Inserted = await rolesRepo.insertOne({
				record: {
					name: 'role1_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const role1Id = (role1Inserted as unknown as { id: string }).id;

			const role2Inserted = await rolesRepo.insertOne({
				record: {
					name: 'role2_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const role2Id = (role2Inserted as unknown as { id: string }).id;

			// Assign permission to role2 only
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: role2Id,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign both roles to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: role1Id,
					create_timestamp: new Date(),
				},
			});

			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: role2Id,
					create_timestamp: new Date(),
				},
			});

			// Should have access through role2
			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource,
			});
			expect(authorized).toBe(true);
		});

		it('should deny when all roles are deactivated', async () => {
			const action = 'all_deactivated_' + Date.now();

			// Create permission
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource: 'data',
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create two roles
			const role1Inserted = await rolesRepo.insertOne({
				record: {
					name: 'role1_deact_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const role1Id = (role1Inserted as unknown as { id: string }).id;

			const role2Inserted = await rolesRepo.insertOne({
				record: {
					name: 'role2_deact_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const role2Id = (role2Inserted as unknown as { id: string }).id;

			// Assign permission to both roles
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: role1Id,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			await rolePermissionsRepo.insertOne({
				record: {
					role_id: role2Id,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign both deactivated roles to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: role1Id,
					create_timestamp: new Date(),
					deactivate_timestamp: new Date(),
				},
			});

			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: role2Id,
					create_timestamp: new Date(),
					deactivate_timestamp: new Date(),
				},
			});

			// Should deny access
			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action: action,
			});
			expect(authorized).toBe(false);
		});

		it('allows at least one active & granting role', async () => {
			const action = 'mixed_deact_' + Date.now();

			// Create permission
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource: 'documents',
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create two roles
			const role1Inserted = await rolesRepo.insertOne({
				record: {
					name: 'role1_mixed_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const role1Id = (role1Inserted as unknown as { id: string }).id;

			const role2Inserted = await rolesRepo.insertOne({
				record: {
					name: 'role2_mixed_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const role2Id = (role2Inserted as unknown as { id: string }).id;

			// Assign permission to both roles
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: role1Id,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			await rolePermissionsRepo.insertOne({
				record: {
					role_id: role2Id,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign one active and one deactivated role to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: role1Id,
					create_timestamp: new Date(),
					deactivate_timestamp: new Date(),
				},
			});

			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: role2Id,
					create_timestamp: new Date(),
				},
			});

			// Should allow access through active role2
			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource: 'documents',
			});
			expect(authorized).toBe(true);
		});
	});

	describe('Coverage for Multiple Permissions', () => {
		it('handles multiple permissions and find matching role', async () => {
			const action = 'coverage_' + Date.now();
			const resource1 = 'resource1_' + Date.now();
			const resource2 = 'resource2_' + Date.now();
			const resource3 = 'resource3_' + Date.now();

			// Create three permissions for the same action
			// 	with different resources
			await permissionsRepo.insertOne({
				record: {
					action,
					resource: resource1,
					create_timestamp: new Date(),
				},
			});

			const perm2Inserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource: resource2,
					create_timestamp: new Date(),
				},
			});
			const perm2Id = (perm2Inserted as unknown as { id: string }).id;

			await permissionsRepo.insertOne({
				record: {
					action,
					resource: resource3,
					create_timestamp: new Date(),
				},
			});

			// Create role
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'coverage_role_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign only the second permission to the role
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: perm2Id,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			// Should allow access with resource2 (second permission)
			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource: resource2,
			});
			expect(authorized).toBe(true);

			// Should deny access with resource1 (not assigned to role)
			const authorizedResource1 = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource: resource1,
			});
			expect(authorizedResource1).toBe(false);

			// Should deny access with resource3 (not assigned to role)
			const authorizedResource3 = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource: resource3,
			});
			expect(authorizedResource3).toBe(false);
		});

		it('supports additional permissions without assignments', async () => {
			const action = 'partial_' + Date.now();
			const resource1 = 'partial1_' + Date.now();
			const resource2 = 'partial2_' + Date.now();

			// Create two permissions
			const perm1Inserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource: resource1,
					create_timestamp: new Date(),
				},
			});
			const perm1Id = (perm1Inserted as unknown as { id: string }).id;

			await permissionsRepo.insertOne({
				record: {
					action,
					resource: resource2,
					create_timestamp: new Date(),
				},
			});

			// Create role
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'partial_role_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign only first permission to role
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: perm1Id,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			// Should allow with resource1 (has permission)
			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource: resource1,
			});
			expect(authorized).toBe(true);

			// Should deny with resource2 (no permission)
			const notAuthorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource: resource2,
			});
			expect(notAuthorized).toBe(false);
		});

		it(
			'should handle multiple permissions where additional ' +
				'exist but have no role assignments',
			async () => {
				const action = 'nocov_' + Date.now();
				const resource1 = 'nocov1_' + Date.now();
				const resource2 = 'nocov2_' + Date.now();
				const resource3 = 'nocov3_' + Date.now();

				// Create three permissions - only one will have role assignment
				const perm1Inserted = await permissionsRepo.insertOne({
					record: {
						action,
						resource: resource1,
						create_timestamp: new Date(),
					},
				});
				const perm1Id = (perm1Inserted as unknown as { id: string }).id;

				await permissionsRepo.insertOne({
					record: {
						action,
						resource: resource2,
						create_timestamp: new Date(),
					},
				});

				await permissionsRepo.insertOne({
					record: {
						action,
						resource: resource3,
						create_timestamp: new Date(),
					},
				});

				// Create role with only the first permission
				const roleInserted = await rolesRepo.insertOne({
					record: {
						name: 'nocov_role_' + Date.now(),
						create_timestamp: new Date(),
					},
				});
				const roleId = (roleInserted as unknown as { id: string }).id;

				// Assign only first permission to role '
				// 	(second and third have no assignment)
				await rolePermissionsRepo.insertOne({
					record: {
						role_id: roleId,
						permission_id: perm1Id,
						create_timestamp: new Date(),
					},
				});

				// Assign role to principal
				await principalRolesRepo.insertOne({
					record: {
						principal_id: testPrincipalId,
						role_id: roleId,
						create_timestamp: new Date(),
					},
				});

				// Should allow with resource1
				const authorized = await rbac.isAuthorized({
					principal: testPrincipal,
					action,
					resource: resource1,
				});
				expect(authorized).toBe(true);

				// Should deny with resource2 and resource3
				const notAuthorizedRes2 = await rbac.isAuthorized({
					principal: testPrincipal,
					action,
					resource: resource2,
				});
				expect(notAuthorizedRes2).toBe(false);

				const notAuthorizedRes3 = await rbac.isAuthorized({
					principal: testPrincipal,
					action,
					resource: resource3,
				});
				expect(notAuthorizedRes3).toBe(false);
			}
		);

		it('handles string error thrown during evaluation', async () => {
			// Create a principal with a role that has a permission
			const action = 'error_test_' + Date.now();
			const resource = 'error_resource_' + Date.now();

			// Create permission
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource,
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create role
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'error_role_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign permission to role
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			// Mock find to throw a non-Error object
			const originalFind = rbac.principalRolesRepo.find;
			let callCount = 0;
			rbac.principalRolesRepo.find = async () => {
				callCount++;
				if (callCount === 1) {
					// First call, throw non-Error object
					throw 'String error message';
				}
				// Fallback to original for other calls
				return originalFind.call(rbac.principalRolesRepo, {
					where: {
						principal_id: testPrincipalId,
						deactivate_timestamp: null,
					},
				});
			};

			// Evaluate should handle non-Error thrown
			const result = await rbac.evaluate({
				principal: testPrincipal,
				action,
				resource,
			});

			expect(result.allowed).toBe(false);
			expect(result.reason).toContain('String error message');

			// Restore original
			rbac.principalRolesRepo.find = originalFind;
		});

		it(
			'handles multiple permissions where some additional ' +
				'perms have no role',
			async () => {
				const action = 'multi_test_' + Date.now();
				const res1 = 'r1_' + Date.now();
				const res2 = 'r2_' + Date.now();
				const res3 = 'r3_' + Date.now();

				// Create three permissions for the same action
				const p1Inserted = await permissionsRepo.insertOne({
					record: {
						action,
						resource: res1,
						create_timestamp: new Date(),
					},
				});
				const p1Id = (p1Inserted as unknown as { id: string }).id;

				await permissionsRepo.insertOne({
					record: {
						action,
						resource: res2,
						create_timestamp: new Date(),
					},
				});

				await permissionsRepo.insertOne({
					record: {
						action,
						resource: res3,
						create_timestamp: new Date(),
					},
				});

				// Create role and assign only first permission
				const roleInserted = await rolesRepo.insertOne({
					record: {
						name: 'test_role_' + Date.now(),
						create_timestamp: new Date(),
					},
				});
				const roleId = (roleInserted as unknown as { id: string }).id;

				// Only assign first permission to role
				await rolePermissionsRepo.insertOne({
					record: {
						role_id: roleId,
						permission_id: p1Id,
						create_timestamp: new Date(),
					},
				});

				// Assign role to principal
				await principalRolesRepo.insertOne({
					record: {
						principal_id: testPrincipalId,
						role_id: roleId,
						create_timestamp: new Date(),
					},
				});

				// Test with res1 (assigned) - should allow
				const auth1 = await rbac.isAuthorized({
					principal: testPrincipal,
					action,
					resource: res1,
				});
				expect(auth1).toBe(true);

				// Test with res2 and res3 (not assigned) - should deny
				const auth2 = await rbac.isAuthorized({
					principal: testPrincipal,
					action,
					resource: res2,
				});
				expect(auth2).toBe(false);

				const auth3 = await rbac.isAuthorized({
					principal: testPrincipal,
					action,
					resource: res3,
				});
				expect(auth3).toBe(false);
			}
		);

		it('verifies all active roles return array not null', async () => {
			const action = 'verify_' + Date.now();
			const resource = 'vres_' + Date.now();

			// Create permission
			const permInserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource,
					create_timestamp: new Date(),
				},
			});
			const permId = (permInserted as unknown as { id: string }).id;

			// Create role
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'vrole_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Assign permission to role
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: permId,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal
			const assignmentInserted = await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			// Verify assignment was created
			expect(assignmentInserted).toBeDefined();

			// Directly test getPrincipalActiveRoles by evaluating
			// This should call getPrincipalActiveRoles which should return
			// actual array from find() - testing the ?? operator left branch
			const result = await rbac.evaluate({
				principal: testPrincipal,
				action,
				resource,
			});

			expect(result.allowed).toBe(true);

			// Also test isAuthorized to ensure active roles are found
			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource,
			});
			expect(authorized).toBe(true);
		});

		it('handles empty additional permission searches', async () => {
			const action = 'empty_additional_' + Date.now();
			const res1 = 'e1_' + Date.now();
			const res2 = 'e2_' + Date.now();
			const res3 = 'e3_' + Date.now();

			// Create three permissions
			const p1Inserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource: res1,
					create_timestamp: new Date(),
				},
			});
			const p1Id = (p1Inserted as unknown as { id: string }).id;

			await permissionsRepo.insertOne({
				record: {
					action,
					resource: res2,
					create_timestamp: new Date(),
				},
			});

			await permissionsRepo.insertOne({
				record: {
					action,
					resource: res3,
					create_timestamp: new Date(),
				},
			});

			// Create role and assign only first permission
			// This ensures additional permissions (2 and 3) have no roles
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'empty_role_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

			// Only assign first permission
			await rolePermissionsRepo.insertOne({
				record: {
					role_id: roleId,
					permission_id: p1Id,
					create_timestamp: new Date(),
				},
			});

			// Assign role to principal
			await principalRolesRepo.insertOne({
				record: {
					principal_id: testPrincipalId,
					role_id: roleId,
					create_timestamp: new Date(),
				},
			});

			// Evaluate with res1 - should work and trigger multiple permission
			// checks
			const auth1 = await rbac.evaluate({
				principal: testPrincipal,
				action,
				resource: res1,
			});
			expect(auth1.allowed).toBe(true);

			// These should fail and hit the empty additional permission case
			const auth2 = await rbac.evaluate({
				principal: testPrincipal,
				action,
				resource: res2,
			});
			expect(auth2.allowed).toBe(false);

			const auth3 = await rbac.evaluate({
				principal: testPrincipal,
				action,
				resource: res3,
			});
			expect(auth3.allowed).toBe(false);
		});
	});

	describe('grantPermission() with Resource', () => {
		it('grants permission with explicit resource parameter', async () => {
			const action = 'edit_' + Date.now();
			const resource = 'documents_' + Date.now();

			// Grant permission with resource
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
				resource,
			});

			// Verify permission was created with the resource
			const permission = await permissionsRepo.findOne({
				where: {
					action,
					resource,
				},
			});

			expect(permission).toBeDefined();
			expect(permission?.action).toBe(action);
			expect(permission?.resource).toBe(resource);

			// Verify role was created and assigned
			const role = await rolesRepo.findOne({
				where: { name: action },
			});

			expect(role).toBeDefined();

			const assignment = await principalRolesRepo.findOne({
				where: {
					principal_id: testPrincipalId,
					role_id: role?.id,
				},
			});

			expect(assignment).toBeDefined();
		});

		it('should reuse existing permission with resource', async () => {
			const action = 'create_' + Date.now();
			const resource = 'posts_' + Date.now();

			// Create permission manually first
			await permissionsRepo.insertOne({
				record: {
					action,
					resource,
					create_timestamp: new Date(),
				},
			});

			// Grant permission using same action and resource
			await rbac.grantPermission({
				principalId: testPrincipalId,
				action,
				resource,
			});

			// Verify only one permission exists
			const permissions = await permissionsRepo.find({
				where: {
					action,
					resource,
				},
			});

			expect((permissions ?? []).length).toBe(1);
		});

		it(
			'should allow authorization with ' + 'resource-specific permission',
			async () => {
				const action = 'delete_' + Date.now();
				const resource = 'comments_' + Date.now();

				// Grant permission with specific resource
				await rbac.grantPermission({
					principalId: testPrincipalId,
					action,
					resource,
				});

				// Should be authorized for the specific resource
				const authorized = await rbac.isAuthorized({
					principal: testPrincipal,
					action,
					resource,
				});

				expect(authorized).toBe(true);

				// Should not be authorized for different resource
				const notAuthorized = await rbac.isAuthorized({
					principal: testPrincipal,
					action,
					resource: 'different_' + Date.now(),
				});

				expect(notAuthorized).toBe(false);
			}
		);
	});
});
