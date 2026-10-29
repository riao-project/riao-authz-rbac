import { RiaoGetListEndpoint } from '@riao/rest';
import { MinLengthValidator, ObjectValSan } from 'valsan';
import { listValidators } from '@riao/rest/endpoints/get-list-endpoint';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * GET /roles/:roleId/permissions - Get all permissions for a role
 */
export class GetRolePermissionsEndpoint extends RiaoGetListEndpoint<any> {
	public override path = '/:roleId/permissions';
	public override description = 'Get all permissions assigned to a role';

	protected auth: RbacAuthorization;

	public override params = new ObjectValSan({
		schema: { roleId: new MinLengthValidator({ minLength: 1 }) },
	});
	public override paramsExample = { roleId: 'role-123' };

	public override queryExample = {
		limit: 100, offset: 0, orderBy: 'id', orderDirection: 'DESC',
	};
	public override query = new ObjectValSan({ schema: listValidators });

	public override inject() {
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', this.auth.rolePermissionsRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest): Promise<any[]> {
		const roleId = request.params?.['roleId'] as string;

		const rolePermissions = await this.auth.rolePermissionsRepo.find({
			where: { role_id: roleId },
		});

		return rolePermissions;
	}
}
