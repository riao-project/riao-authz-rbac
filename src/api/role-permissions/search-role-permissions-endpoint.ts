import { RiaoSearchEndpoint } from '@riao/rest';
import { RiaoSearchColumn } from '@riao/rest/endpoints/search-endpoint';
import { RbacAuthorization, RbacRolePermission } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

type SearchRolePermission = RbacRolePermission & { id: string };

export class SearchRolePermissionsEndpoint
	extends RiaoSearchEndpoint<SearchRolePermission> {
	public override description = 'Search RBAC role-permission assignments';
	public override bodyExample = {
		limit: 100, offset: 0,
		order: [{ column: 'id', direction: 'ASC' }],
	};

	public override inject() {
		const auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', auth.rolePermissionsRepo);
		super.inject();
	}

	protected override getColumnMap():
		Record<string, RiaoSearchColumn<SearchRolePermission>> {
		return {
			id: { column: 'id' },
			role_id: { column: 'role_id' },
			permission_id: { column: 'permission_id' },
			create_timestamp: { column: 'create_timestamp' },
		};
	}
}
