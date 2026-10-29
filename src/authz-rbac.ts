import {
	and,
	DatabaseRecordId,
	Expression,
	inArray,
	or,
	QueryRepository,
	SelectQuery,
} from '@riao/dbal';
import { KeyValExpression } from '@riao/dbal/expression/key-val-expression';
import {
	Authorization,
	AuthorizationContext,
	AuthorizationResult,
	AuthorizationOptions,
	AuthorizationSubject,
} from '@riao/iam/authorization';
import { Principal } from '@riao/iam/auth';
import { identifier } from '@riao/dbal/expression/identifier';

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
	deactivate_timestamp?: Date | null;
}

export type RbacAuthorizationOptions = AuthorizationOptions;

export interface CheckRolesHavePermissionContext {
	roleIds: DatabaseRecordId[];
	action: string;
	resource?: string;
}

/**
 * Role-Based Access Control (RBAC) implementation of Authorization
 * RBAC uses roles as an intermediary between principals and permissions
 * Evaluation flow: Principal -> Roles -> Permissions -> Authorization decision
 */
export class RbacAuthorization extends Authorization<
	Principal, AuthorizationSubject
> {
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

	public async role(
		options: { name: string; description?: string }
	): Promise<DatabaseRecordId> {
		if (!options.name?.trim()) {
			throw new TypeError('Role name must be a non-empty string');
		}

		const existing = await this.rolesRepo.findOne({
			where: { name: options.name },
		});

		if (existing) {
			return existing.id;
		}

		const { id } = await this.rolesRepo.insertOne({
			record: { ...options, create_timestamp: new Date() },
		});

		if (id === undefined) {
			throw new Error('Role creation returned no ID');
		}

		return id;
	}

	public async permission(
		options: { action: string; resource?: string; description?: string }
	): Promise<DatabaseRecordId> {
		if (
			!options.action?.trim() ||
			(options.resource !== undefined && !options.resource.trim())
		) {
			throw new TypeError(
				'Permission action and optional resource must be ' +
				'non-empty strings'
			);
		}

		const resource = options.resource ?? null;
		const existing = await this.permissionsRepo.findOne({
			where: { action: options.action, resource },
		});

		if (existing) {
			return existing.id;
		}

		const { id } = await this.permissionsRepo.insertOne({
			record: { ...options, resource, create_timestamp: new Date() },
		});

		if (id === undefined) {
			throw new Error('Permission creation returned no ID');
		}

		return id;
	}

	public async addPermissionToRole(
		options: { roleId: DatabaseRecordId; permissionId: DatabaseRecordId }
	): Promise<void> {
		const where = {
			role_id: options.roleId,
			permission_id: options.permissionId,
		};

		const existing = await this.rolePermissionsRepo.findOne({ where });
		if (!existing) {
			await this.rolePermissionsRepo.insertOne({
				record: { ...where, create_timestamp: new Date() },
			});
		}
	}

	public async assignRole(
		options: { principalId: DatabaseRecordId; roleId: DatabaseRecordId }
	): Promise<void> {
		const where = {
			principal_id: options.principalId,
			role_id: options.roleId,
		};
		const existing = await this.principalRolesRepo.findOne({ where });

		if (existing) {
			if (existing.deactivate_timestamp) {
				await this.principalRolesRepo.update({
					where: { id: existing.id },
					set: { deactivate_timestamp: null },
				});
			}
		}
		else {
			await this.principalRolesRepo.insertOne({
				record: { ...where, create_timestamp: new Date() },
			});
		}
	}

	/**
	 * Evaluate authorization using RBAC model
	 * Checks if principal has a role that contains the required permission
	 * @param context The authorization context
	 * @returns Authorization result
	 */
	public async evaluate(
		context: AuthorizationContext<AuthorizationSubject>
	): Promise<AuthorizationResult> {
		if (
			typeof context.principal?.id !== 'string' ||
			!context.principal.id.trim() ||
			typeof context.action !== 'string' || !context.action.trim() ||
			(context.resource !== undefined &&
				(typeof context.resource !== 'string' ||
					!context.resource.trim()))
		) {
			throw new TypeError(
				'RBAC requires a principal ID, action, ' +
				'and optional string resource'
			);
		}

		const principalRoles = await this.getPrincipalActiveRoles(
			context.principal.id
		);

		if (principalRoles.length === 0) {
			return {
				allowed: false,
				reason: 'Principal has no active roles',
			};
		}

		const roleIds = principalRoles.map((pr) => pr.role_id);
		const hasPermission = await this.checkRolesHavePermission({
			roleIds,
			action: context.action,
			resource: context.resource,
		});

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
	 * Uses a single optimized query with joins instead of N+1 queries
	 * @param context The check context containing roleIds, action,
	 * 	and optional resource
	 * @returns True if at least one role has the permission
	 */
	private async checkRolesHavePermission(
		context: CheckRolesHavePermissionContext
	): Promise<boolean> {
		const { roleIds, action, resource } = context;
		const query: SelectQuery<RbacRolePermission> = {
			table: 'iam_rbac_role_permissions',
			join: [
				{
					type: 'INNER',
					table: 'iam_rbac_permissions',
					on: {
						'iam_rbac_permissions.id': identifier(
							'iam_rbac_role_permissions.permission_id'
						),
					},
				},
			],
			where: [
				{ 'iam_rbac_permissions.action': action },
				and,
				{
					'iam_rbac_role_permissions.role_id': inArray(roleIds),
				} as Expression,
			] as Expression,
		};

		if (resource) {
			// If resource is specified, add condition for matching
			// 	resource or global on resource type (null)
			(query.where! as Expression[]).push(
				...[
					and,
					[
						{ 'iam_rbac_permissions.resource': resource },
						or,
						{ 'iam_rbac_permissions.resource': null },
					],
				]
			);
		}
		else {
			// If no resource specified, only match global permissions
			(query.where! as Expression[]).push(
				...[and, { 'iam_rbac_permissions.resource': null }]
			);
		}

		// Execute the query to get all role-permissions matching
		// the criteria and the requested roleIds in a single database call
		const rolePermissions = await this.rolePermissionsRepo.find(query);

		// Return true if any matching role-permissions were found
		return rolePermissions && rolePermissions.length > 0;
	}
}
