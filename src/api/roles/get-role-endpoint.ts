import { RiaoGetOneEndpoint } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * GET /roles/:roleId - Get a specific role
 */
export class GetRoleEndpoint extends RiaoGetOneEndpoint<any> {
	public override path = '/roles/:roleId';
	public override description = 'Get a specific RBAC role by ID';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(request: ApiRequest): Promise<any> {
		const roleId = request.params?.['roleId'] as string;

		const role = await this.auth.rolesRepo.findOne({
			where: { id: roleId },
		});

		return role;
	}
}
