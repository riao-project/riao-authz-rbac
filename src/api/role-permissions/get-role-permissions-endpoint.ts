import { RiaoGetListEndpoint } from '@riao/rest';
import { ObjectValSan } from 'valsan';
import { listValidators } from '@riao/rest/endpoints/get-list-endpoint';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * GET /role-permissions - Get role-permission assignments
 */
export class GetRolePermissionsEndpoint extends RiaoGetListEndpoint<any> {
	public override path = '/';
	public override description = 'Get RBAC role-permission assignments';

	protected auth: RbacAuthorization;

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
}
