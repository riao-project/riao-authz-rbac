import { RiaoSearchEndpoint } from '@riao/rest';
import { RiaoSearchColumn } from '@riao/rest/endpoints/search-endpoint';
import { RbacAuthorization, RbacPermission } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

type SearchPermission = RbacPermission & { id: string };

export class SearchPermissionsEndpoint
	extends RiaoSearchEndpoint<SearchPermission> {
	public override description = 'Search RBAC permissions';
	public override bodyExample = {
		limit: 100, offset: 0,
		order: [{ column: 'id', direction: 'ASC' }],
	};

	public override inject() {
		const auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', auth.permissionsRepo);
		super.inject();
	}

	protected override getColumnMap():
		Record<string, RiaoSearchColumn<SearchPermission>> {
		return {
			id: { column: 'id' },
			action: { column: 'action' },
			resource: { column: 'resource' },
			description: { column: 'description' },
			create_timestamp: { column: 'create_timestamp' },
		};
	}
}
