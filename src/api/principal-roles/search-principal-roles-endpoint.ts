import { RiaoSearchEndpoint } from '@riao/rest';
import { RiaoSearchColumn } from '@riao/rest/endpoints/search-endpoint';
import { RbacAuthorization, RbacPrincipalRole } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

type SearchPrincipalRole = RbacPrincipalRole & { id: string };

export class SearchPrincipalRolesEndpoint
	extends RiaoSearchEndpoint<SearchPrincipalRole> {
	public override description = 'Search RBAC principal-role assignments';
	public override bodyExample = {
		limit: 100, offset: 0,
		order: [{ column: 'id', direction: 'ASC' }],
	};

	public override inject() {
		const auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', auth.principalRolesRepo);
		super.inject();
	}

	protected override getColumnMap():
		Record<string, RiaoSearchColumn<SearchPrincipalRole>> {
		return {
			id: { column: 'id' },
			principal_id: { column: 'principal_id' },
			role_id: { column: 'role_id' },
			create_timestamp: { column: 'create_timestamp' },
			deactivate_timestamp: { column: 'deactivate_timestamp' },
		};
	}
}
