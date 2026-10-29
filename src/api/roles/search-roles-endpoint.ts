import { RiaoSearchEndpoint } from '@riao/rest';
import { RiaoSearchColumn } from '@riao/rest/endpoints/search-endpoint';
import { RbacAuthorization, RbacRole } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

type SearchRole = RbacRole & { id: string };

export class SearchRolesEndpoint extends RiaoSearchEndpoint<SearchRole> {
	public override description = 'Search RBAC roles';
	public override bodyExample = {
		limit: 100, offset: 0,
		order: [{ column: 'id', direction: 'ASC' }],
	};

	public override inject() {
		const auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', auth.rolesRepo);
		super.inject();
	}

	protected override getColumnMap():
		Record<string, RiaoSearchColumn<SearchRole>> {
		return {
			id: { column: 'id' },
			name: { column: 'name' },
			description: { column: 'description' },
			create_timestamp: { column: 'create_timestamp' },
			deactivate_timestamp: { column: 'deactivate_timestamp' },
		};
	}
}
