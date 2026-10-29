import { RiaoGetListEndpoint } from '@riao/rest';
import { MinLengthValidator, ObjectValSan } from 'valsan';
import { listValidators } from '@riao/rest/endpoints/get-list-endpoint';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * GET /principals/:principalId/roles - Get roles for principal
 */
export class GetPrincipalRolesEndpoint extends RiaoGetListEndpoint<any> {
	public override path = '/:principalId/roles';
	public override description = 'Get RBAC roles assigned to a principal';

	protected auth: RbacAuthorization;

	public override params = new ObjectValSan({
		schema: { principalId: new MinLengthValidator({ minLength: 1 }) },
	});
	public override paramsExample = { principalId: 'principal-123' };

	public override queryExample = {
		limit: 100, offset: 0, orderBy: 'id', orderDirection: 'DESC',
	};
	public override query = new ObjectValSan({ schema: listValidators });

	public override inject() {
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', this.auth.principalRolesRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest): Promise<any[]> {
		const principalId = request.params?.['principalId'] as string;

		const roles = await this.auth.principalRolesRepo.find({
			where: { principal_id: principalId },
		});

		return roles;
	}
}
