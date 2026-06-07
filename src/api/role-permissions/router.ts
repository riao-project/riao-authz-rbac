import { RiaoRouter } from '@riao/rest';
import { AddPermissionToRoleEndpoint } from './add-permission-to-role-endpoint';
import { RemovePermissionFromRoleEndpoint } from './remove-permission-from-role-endpoint';
import { GetRolePermissionsEndpoint } from './get-role-permissions-endpoint';

/**
 * Router for role-permission management endpoints
 */
export class RolePermissionsRouter extends RiaoRouter {
	public override path = '/roles';

	protected async routes(): Promise<any[]> {
		return [
			GetRolePermissionsEndpoint,
			AddPermissionToRoleEndpoint,
			RemovePermissionFromRoleEndpoint,
		];
	}
}
