import { RiaoGetListEndpoint } from '@riao/rest';
import { ObjectValSan } from 'valsan';
import { listValidators } from '@riao/rest/endpoints/get-list-endpoint';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * GET /permissions - Get all permissions
 */
export class GetPermissionsEndpoint extends RiaoGetListEndpoint<any> {
	public override path = '/';
	public override description = 'Get all RBAC permissions';

	protected auth: RbacAuthorization;

	public override queryExample = {
		limit: 100, offset: 0, orderBy: 'id', orderDirection: 'DESC',
	};
	public override query = new ObjectValSan({ schema: listValidators });

	public override inject() {
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', this.auth.permissionsRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest): Promise<any[]> {
		const permissions = await this.auth.permissionsRepo.find({});

		return permissions;
	}
}
