import { RiaoGetListEndpoint } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import type { RbacAuthorization, RbacRole } from '../../authz-rbac';

/**
 * GET /roles - Get all roles
 */
export class GetRolesEndpoint extends RiaoGetListEndpoint<any> {
	public override path = '/roles';
	public override description = 'Get all RBAC roles';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>('auth');
	}

	public override async handle(
		request: ApiRequest,
		response: ApiResponse,
		next: ApiNextFunction
	): Promise<any[]> {
		const roles = await this.auth.rolesRepo.find({});
		return roles;
	}
}
