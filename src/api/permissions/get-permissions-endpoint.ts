import { RiaoGetListEndpoint } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * GET /permissions - Get all permissions
 */
export class GetPermissionsEndpoint extends RiaoGetListEndpoint<any> {
	public override path = '/permissions';
	public override description = 'Get all RBAC permissions';

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
		const permissions = await this.auth.permissionsRepo.find({});

		return permissions;
	}
}
