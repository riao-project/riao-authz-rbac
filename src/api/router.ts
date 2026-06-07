import { RiaoRouter } from '@riao/rest';
import { RolesRouter } from './roles/router';
import { PermissionsRouter } from './permissions/router';
import { RolePermissionsRouter } from './role-permissions/router';
import { PrincipalRolesRouter } from './principal-roles/router';
import { EvaluateRouter } from './evaluate/router';
import type { RbacAuthorization } from '../authz-rbac';

/**
 * Default RBAC authorization router
 * Composes all domain routers for role, permission, role-permission, principal-role, and evaluate management
 */
export class DefaultRbacAuthzRouter extends RiaoRouter {
	public override path = '/rbac';

	protected async routes(): Promise<any[]> {
		return [
			RolesRouter,
			PermissionsRouter,
			RolePermissionsRouter,
			PrincipalRolesRouter,
			EvaluateRouter,
		];
	}
}
