import { RiaoRouter } from '@riao/rest';
import {
	SearchRolePermissionsEndpoint,
} from './search-role-permissions-endpoint';
import { AddPermissionToRoleEndpoint } from './add-permission-to-role-endpoint';
import {
	RemovePermissionFromRoleEndpoint,
} from './remove-permission-from-role-endpoint';
import { GetRolePermissionsEndpoint } from './get-role-permissions-endpoint';

/**
 * Router for role-permission management endpoints
 */
export class RolePermissionsRouter extends RiaoRouter {
	public override path = '/role-permissions';

	protected override async routes() {
		return [
			AddPermissionToRoleEndpoint,
			GetRolePermissionsEndpoint,
			SearchRolePermissionsEndpoint,
			RemovePermissionFromRoleEndpoint,
		];
	}
}
