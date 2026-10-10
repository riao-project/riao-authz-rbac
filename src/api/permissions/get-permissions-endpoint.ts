import { RiaoGetListEndpoint } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * GET /permissions - Get all permissions
 */
export class GetPermissionsEndpoint extends RiaoGetListEndpoint<any> {
	public override path = '/permissions';
	public override description = 'Get all RBAC permissions';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(request: ApiRequest): Promise<any[]> {
		const permissions = await this.auth.permissionsRepo.find({});

		return permissions;
	}
}
