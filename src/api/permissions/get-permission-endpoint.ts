import { RiaoGetOneEndpoint } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * GET /permissions/:permissionId - Get a specific permission
 */
export class GetPermissionEndpoint extends RiaoGetOneEndpoint<any> {
	public override path = '/permissions/:permissionId';
	public override description = 'Get a specific RBAC permission by ID';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(request: ApiRequest): Promise<any> {
		const permissionId = request.params?.['permissionId'] as string;

		const permission = await this.auth.permissionsRepo.findOne({
			where: { id: permissionId },
		});

		return permission;
	}
}
