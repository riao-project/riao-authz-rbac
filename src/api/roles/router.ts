import { RiaoRouter } from '@riao/rest';
import { CreateRoleEndpoint } from './create-role-endpoint';
import { GetRolesEndpoint } from './get-roles-endpoint';
import { GetRoleEndpoint } from './get-role-endpoint';
import { UpdateRoleEndpoint } from './update-role-endpoint';
import { DeleteRoleEndpoint } from './delete-role-endpoint';
import { SearchRolesEndpoint } from './search-roles-endpoint';

/**
 * Router for role management endpoints
 */
export class RolesRouter extends RiaoRouter {
	public override path = '/roles';

	protected async routes(): Promise<any[]> {
		return [
			CreateRoleEndpoint,
			GetRolesEndpoint,
			SearchRolesEndpoint,
			GetRoleEndpoint,
			UpdateRoleEndpoint,
			DeleteRoleEndpoint,
		];
	}
}
