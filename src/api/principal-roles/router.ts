import { RiaoRouter } from '@riao/rest';
import {
	SearchPrincipalRolesEndpoint,
} from './search-principal-roles-endpoint';
import {
	AssignRoleToPrincipalEndpoint,
} from './assign-role-to-principal-endpoint';
import {
	RemoveRoleFromPrincipalEndpoint,
} from './remove-role-from-principal-endpoint';
import { GetPrincipalRolesEndpoint } from './get-principal-roles-endpoint';

/**
 * Router for principal-role management endpoints
 */
export class PrincipalRolesRouter extends RiaoRouter {
	public override path = '/principal-roles';

	protected override async routes() {
		return [
			AssignRoleToPrincipalEndpoint,
			GetPrincipalRolesEndpoint,
			SearchPrincipalRolesEndpoint,
			RemoveRoleFromPrincipalEndpoint,
		];
	}
}
