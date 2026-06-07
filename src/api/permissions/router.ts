import { RiaoRouter } from '@riao/rest';
import { CreatePermissionEndpoint } from './create-permission-endpoint';
import { GetPermissionsEndpoint } from './get-permissions-endpoint';
import { GetPermissionEndpoint } from './get-permission-endpoint';
import { UpdatePermissionEndpoint } from './update-permission-endpoint';
import { DeletePermissionEndpoint } from './delete-permission-endpoint';

/**
 * Router for permission management endpoints
 */
export class PermissionsRouter extends RiaoRouter {
	public override path = '/permissions';

	protected async routes(): Promise<any[]> {
		return [
			CreatePermissionEndpoint,
			GetPermissionsEndpoint,
			GetPermissionEndpoint,
			UpdatePermissionEndpoint,
			DeletePermissionEndpoint,
		];
	}
}
