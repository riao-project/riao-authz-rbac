import { RiaoGetOneEndpoint } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * GET /permissions/:permissionId - Get a specific permission
 */
export class GetPermissionEndpoint extends RiaoGetOneEndpoint<any> {
	public override path = '/permissions/:permissionId';
	public override description = 'Get a specific RBAC permission by ID';

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
		const permissionId = request.params?.permissionId as string;

		const permission = await this.auth.permissionsRepo.findOne({
			where: { id: permissionId },
		});

		return permission;
	}
}
