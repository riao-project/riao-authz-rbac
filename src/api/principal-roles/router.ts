import { RiaoRouter } from '@riao/rest';
import { AssignRoleToPrincipalEndpoint } from './assign-role-to-principal-endpoint';
import { RemoveRoleFromPrincipalEndpoint } from './remove-role-from-principal-endpoint';
import { GetPrincipalRolesEndpoint } from './get-principal-roles-endpoint';

/**
 * Router for principal-role management endpoints
 */
export class PrincipalRolesRouter extends RiaoRouter {
	public override path = '/principals';

	protected async routes(): Promise<any[]> {
		return [
			AssignRoleToPrincipalEndpoint,
			RemoveRoleFromPrincipalEndpoint,
			GetPrincipalRolesEndpoint,
		];
	}
}
