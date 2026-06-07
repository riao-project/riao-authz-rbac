import { RiaoGetOneEndpoint } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * GET /roles/:roleId - Get a specific role
 */
export class GetRoleEndpoint extends RiaoGetOneEndpoint<any> {
	public override path = '/roles/:roleId';
	public override description = 'Get a specific RBAC role by ID';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>('auth');
	}

	public override async handle(
		request: ApiRequest,
		response: ApiResponse,
		next: ApiNextFunction
	): Promise<any> {
		const roleId = request.params?.roleId as string;

		const role = await this.auth.rolesRepo.findOne({
			where: { id: roleId },
		});

		return role;
	}
}
