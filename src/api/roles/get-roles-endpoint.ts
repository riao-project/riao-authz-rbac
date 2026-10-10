import { RiaoGetListEndpoint } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import type { RbacAuthorization, RbacRole } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * GET /roles - Get all roles
 */
export class GetRolesEndpoint extends RiaoGetListEndpoint<any> {
	public override path = '/roles';
	public override description = 'Get all RBAC roles';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(request: ApiRequest): Promise<any[]> {
		const roles = await this.auth.rolesRepo.find({});
		return roles;
	}
}
