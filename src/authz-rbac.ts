import { DatabaseRecordId, QueryRepository } from '@riao/dbal';
import { KeyValExpression } from '@riao/dbal/expression/key-val-expression';
import { inArray } from '@riao/dbal/comparison';
import {
	Authorization,
	AuthorizationContext,
	AuthorizationResult,
	AuthorizationOptions,
} from '@riao/iam/authorization';
import { Principal } from '@riao/iam/auth';

export interface RbacRole {
	id: DatabaseRecordId;
	name: string;
	description?: string;
	create_timestamp: Date;
	deactivate_timestamp?: Date;
}

export interface RbacPermission {
	id: DatabaseRecordId;
	action: string;
	resource: string | null;
	description?: string;
	create_timestamp: Date;
}

export interface RbacRolePermission {
	id: DatabaseRecordId;
	role_id: DatabaseRecordId;
	permission_id: DatabaseRecordId;
	create_timestamp: Date;
}

export interface RbacPrincipalRole {
	id: DatabaseRecordId;
	principal_id: DatabaseRecordId;
	role_id: DatabaseRecordId;
	create_timestamp: Date;
	deactivate_timestamp?: Date;
}

export type RbacAuthorizationOptions = AuthorizationOptions;

export interface GrantPermissionOptions {
	principalId: DatabaseRecordId;
	action: string;
	resource?: string;
}

export interface RevokePermissionOptions {
	principalId: DatabaseRecordId;
	action: string;
}

/**
 * Role-Based Access Control (RBAC) implementation of Authorization
 * RBAC uses roles as an intermediary between principals and permissions
 * Evaluation flow: Principal -> Roles -> Permissions -> Authorization decision
 */
export class RbacAuthorization extends Authorization<Principal> {
	public rolesRepo: QueryRepository<RbacRole>;
	public permissionsRepo: QueryRepository<RbacPermission>;
	public rolePermissionsRepo: QueryRepository<RbacRolePermission>;
	public principalRolesRepo: QueryRepository<RbacPrincipalRole>;

	public constructor(options: RbacAuthorizationOptions) {
		// Call parent constructor with required db property
		super({ db: options.db });

		// Initialize repositories for RBAC tables
		this.rolesRepo = options.db.getQueryRepository<RbacRole>({
			table: 'iam_rbac_roles',
			identifiedBy: 'id',
		});

		this.permissionsRepo = options.db.getQueryRepository<RbacPermission>({
			table: 'iam_rbac_permissions',
			identifiedBy: 'id',
		});

		this.rolePermissionsRepo =
			options.db.getQueryRepository<RbacRolePermission>({
				table: 'iam_rbac_role_permissions',
				identifiedBy: 'id',
			});

		this.principalRolesRepo =
			options.db.getQueryRepository<RbacPrincipalRole>({
				table: 'iam_rbac_principal_roles',
				identifiedBy: 'id',
			});
	}

	/**
	 * Evaluate authorization using RBAC model
	 * Checks if principal has a role that contains the required permission
	 * @param context The authorization context
	 * @returns Authorization result
	 */
	public async evaluate(
		context: AuthorizationContext<Principal>
	): Promise<AuthorizationResult> {
		try {
			// Get all active roles for the principal
			const principalRoles = await this.getPrincipalActiveRoles(
				context.principal.id
			);

			if (principalRoles.length === 0) {
				return {
					allowed: false,
					reason: 'Principal has no active roles',
				};
			}

			// Check if any role has the required permission
			const roleIds = principalRoles.map((pr) => pr.role_id);
			const hasPermission = await this.checkRolesHavePermission(
				roleIds,
				context.action,
				context.resource as string | undefined
			);

			if (hasPermission) {
				return {
					allowed: true,
				};
			}

			return {
				allowed: false,
				reason: 'Principal roles do not have required permission',
			};
		}
		catch (error) {
			return {
				allowed: false,
				reason:
					'Authorization evaluation error: ' +
					(error instanceof Error ? error.message : String(error)),
			};
		}
	}

	/**
	 * Grant a permission to a principal by assigning a role
	 * In RBAC, permissions are granted through role assignment
	 * @param options The grant permission options
	 */
	public async grantPermission(
		options: GrantPermissionOptions
	): Promise<void> {
		const { principalId, action, resource } = options;

		// Find or create role by action name
		const role = await this.rolesRepo.findOne({
			where: { name: action } as KeyValExpression<RbacRole>,
		});

		let roleId: DatabaseRecordId;
		if (role) {
			roleId = role.id;
		}
		else {
			// Create role if it doesn't exist
			const { id } = await this.rolesRepo.insertOne({
				record: {
					name: action,
					description: `Role for ${action} action`,
					create_timestamp: new Date(),
				} as unknown as RbacRole,
			});

			roleId = id!;
		}

		// Find or create permission for this action
		const permission = await this.permissionsRepo.findOne({
			where: {
				action,
				resource: resource || null,
			} as KeyValExpression<RbacPermission>,
		});

		let permissionId: DatabaseRecordId;
		if (permission) {
			permissionId = permission.id;
		}
		else {
			// Create permission if it doesn't exist
			const { id } = await this.permissionsRepo.insertOne({
				record: {
					action,
					resource: resource || null,
					create_timestamp: new Date(),
				} as unknown as RbacPermission,
			});

			permissionId = id!;
		}

		// Assign permission to role
		await this.rolePermissionsRepo.insertOne({
			record: {
				role_id: roleId,
				permission_id: permissionId,
				create_timestamp: new Date(),
			} as unknown as RbacRolePermission,
		});

		// Assign role to principal
		await this.principalRolesRepo.insertOne({
			record: {
				principal_id: principalId,
				role_id: roleId,
				create_timestamp: new Date(),
			} as unknown as RbacPrincipalRole,
		});
	}

	/**
	 * Revoke a permission from a principal
	 * In RBAC, permissions are revoked by deactivating role assignment
	 * @param options The revoke permission options
	 */
	public async revokePermission(
		options: RevokePermissionOptions
	): Promise<void> {
		const { principalId, action } = options;
		// Find role by action name
		const role = await this.rolesRepo.findOne({
			where: { name: action } as KeyValExpression<RbacRole>,
		});

		if (!role) {
			return; // Role doesn't exist, nothing to revoke
		}

		const roleId = role.id;

		// Find principal's role assignment
		const assignment = await this.principalRolesRepo.findOne({
			where: {
				principal_id: principalId,
				role_id: roleId,
			} as KeyValExpression<RbacPrincipalRole>,
		});

		if (assignment) {
			// Deactivate the assignment
			await this.principalRolesRepo.update({
				set: {
					deactivate_timestamp: new Date(),
				} as Partial<RbacPrincipalRole>,
				where: {
					id: assignment.id,
				} as KeyValExpression<RbacPrincipalRole>,
			});
		}
	}

	/**
	 * Get all active roles for a principal
	 * @param principalId The principal ID
	 * @returns Array of active role assignments
	 */
	private async getPrincipalActiveRoles(
		principalId: DatabaseRecordId
	): Promise<RbacPrincipalRole[]> {
		const assignments = await this.principalRolesRepo.find({
			where: {
				principal_id: principalId,
				deactivate_timestamp: null,
			} as KeyValExpression<RbacPrincipalRole>,
		});

		return assignments;
	}

	/**
	 * Check if any of the given roles have the required permission
	 * @param roleIds Array of role IDs
	 * @param action The required action
	 * @param resource Optional resource identifier
	 * @returns True if at least one role has the permission
	 */
	private async checkRolesHavePermission(
		roleIds: DatabaseRecordId[],
		action: string,
		resource?: string
	): Promise<boolean> {
		// Get all permissions for this action
		const permissions = await this.permissionsRepo.find({
			where: {
				action,
			} as KeyValExpression<RbacPermission>,
		});

		if (!permissions || permissions.length === 0) {
			return false;
		}

		// Filter permissions based on resource matching
		let matchingPermissions: RbacPermission[];

		if (resource) {
			// If resource is provided, match:
			// 1. Permissions with the exact resource
			// 2. Permissions with null resource (action-only permissions)
			matchingPermissions = permissions.filter(
				(p) => p.resource === resource || p.resource === null
			);
		}
		else {
			// If no resource provided, only match permissions with null
			// 	resource
			// (action-only permissions, no specific resource requirement)
			matchingPermissions = permissions.filter(
				(p) => p.resource === null
			);
		}

		if (matchingPermissions.length === 0) {
			return false;
		}

		// Get permission IDs to check
		const permissionIds = matchingPermissions.map((p) => p.id);

		// Check if any role has any of these permissions using IN clause
		const rolePermissions = await this.rolePermissionsRepo.find({
			where: {
				permission_id: inArray(permissionIds),
			} as KeyValExpression<RbacRolePermission>,
		});

		if (!rolePermissions || rolePermissions.length === 0) {
			return false;
		}

		// Check if any of the requested roles have any matching permission
		const rolePermissionMap = new Set(
			rolePermissions.map((rp) => rp.role_id)
		);

		// Check if any of the requested roles have permission
		return roleIds.some((roleId) => rolePermissionMap.has(roleId));
	}
}
