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

	describe('named role management', () => {
		it('omits direct permission shortcuts', () => {
			expect('grantPermission' in rbac).toBeFalse();
			expect('revokePermission' in rbac).toBeFalse();
		});

		it('reuses roles, permissions, links, and principal assignments', async () => {
			const name = `administrator_${testPrincipalId}`;
			const roleId = await rbac.role({ name });
			expect(await rbac.role({ name })).toBe(roleId);
			const options = { action: 'manage', resource: name };
			const permissionId = await rbac.permission(options);
			expect(await rbac.permission(options))
				.toBe(permissionId);

			for (let attempt = 0; attempt < 2; attempt++) {
				await rbac.addPermissionToRole({ roleId, permissionId });
				await rbac.assignRole({
					roleId, principalId: testPrincipalId,
				});
			}
			expect((await rolePermissionsRepo.find({
				where: { role_id: roleId, permission_id: permissionId },
			})).length).toBe(1);
			expect((await principalRolesRepo.find({
				where: { principal_id: testPrincipalId, role_id: roleId },
			})).length).toBe(1);
			expect(await rbac.isAuthorized({
				principal: testPrincipal, ...options,
			})).toBeTrue();
		});

		it('reactivates an assignment without creating a duplicate', async () => {
			const roleId = await rbac.role({
				name: `reactivate_${testPrincipalId}`,
			});
			const permissionId = await rbac.permission({
				action: 'reactivate', resource: testPrincipalId,
			});
			await rbac.addPermissionToRole({ roleId, permissionId });
			await rbac.assignRole({ roleId, principalId: testPrincipalId });
			const where = { role_id: roleId, principal_id: testPrincipalId };
			await principalRolesRepo.update({
				where, set: { deactivate_timestamp: new Date() },
			});
			await rbac.assignRole({ roleId, principalId: testPrincipalId });
			const assignments = await principalRolesRepo.find({ where });
			expect(assignments.length).toBe(1);
			expect(assignments[0].deactivate_timestamp).toBeNull();
			expect(await rbac.isAuthorized({
				principal: testPrincipal,
				action: 'reactivate', resource: testPrincipalId,
			})).toBeTrue();
		});

		it('fails explicitly if an inserted record has no ID', async () => {
			spyOn(rolesRepo, 'insertOne').and.resolveTo({});
			await expectAsync(rbac.role({
				name: `no_id_${testPrincipalId}`,
			})).toBeRejectedWithError('Role creation returned no ID');
			spyOn(permissionsRepo, 'insertOne').and.resolveTo({});
			await expectAsync(rbac.permission({
				action: 'missing-id', resource: testPrincipalId,
			})).toBeRejectedWithError('Permission creation returned no ID');
		});

		it('preserves database failures and rejects empty policy names', async () => {
			await expectAsync(rbac.role({ name: ' ' }))
				.toBeRejectedWithError(TypeError);
			await expectAsync(rbac.permission({ action: ' ' }))
				.toBeRejectedWithError(TypeError);
			const failure = new Error('Database unavailable');
			spyOn(rolesRepo, 'findOne').and.rejectWith(failure);
			await expectAsync(rbac.role({ name: 'admin' }))
				.toBeRejectedWith(failure);
		});
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

		it('propagates invalid database identifiers', async () => {
			await expectAsync(rbac.evaluate({
				principal: { id: 'invalid-id' },
				action: 'read',
			})).toBeRejected();
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

				// Assign only first permission to role
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

			await expectAsync(rbac.evaluate({
				principal: testPrincipal,
				action,
				resource,
			})).toBeRejectedWith('String error message');

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

		// eslint-disable-next-line max-len
		it('regression: allows access when role is assigned to 2nd permission not 1st', async () => {
			const action = 'regression_' + Date.now();
			const res1 = 'reg_res1_' + Date.now();
			const res2 = 'reg_res2_' + Date.now();

			// Create two permissions for the same action
			await permissionsRepo.insertOne({
				record: {
					action,
					resource: res1,
					create_timestamp: new Date(),
				},
			});

			const perm2Inserted = await permissionsRepo.insertOne({
				record: {
					action,
					resource: res2,
					create_timestamp: new Date(),
				},
			});
			const perm2Id = (perm2Inserted as unknown as { id: string }).id;

			// Create role and assign ONLY the second permission
			// (first permission has no role assignment)
			const roleInserted = await rolesRepo.insertOne({
				record: {
					name: 'regression_role_' + Date.now(),
					create_timestamp: new Date(),
				},
			});
			const roleId = (roleInserted as unknown as { id: string }).id;

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

			// Should allow access to res2 (has permission assigned to role)
			const authorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource: res2,
			});
			expect(authorized).toBe(true);

			// Should deny access to res1 (no permission assigned to role)
			const notAuthorized = await rbac.isAuthorized({
				principal: testPrincipal,
				action,
				resource: res1,
			});
			expect(notAuthorized).toBe(false);
		});
	});


});
