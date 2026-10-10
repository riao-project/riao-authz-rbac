import { RiaoGetListEndpoint } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * GET /roles/:roleId/permissions - Get all permissions for a role
 */
export class GetRolePermissionsEndpoint extends RiaoGetListEndpoint<any> {
	public override path = '/roles/:roleId/permissions';
	public override description = 'Get all permissions assigned to a role';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(request: ApiRequest): Promise<any[]> {
		const roleId = request.params?.['roleId'] as string;

		const rolePermissions = await this.auth.rolePermissionsRepo.find({
			where: { role_id: roleId },
		});

		return rolePermissions;
	}
}
