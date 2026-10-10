import { RiaoGetListEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * GET /principals/:principalId/roles - Get roles for principal
 */
export class GetPrincipalRolesEndpoint extends RiaoGetListEndpoint<any> {
	public override path = '/principals/:principalId/roles';
	public override description = 'Get RBAC roles assigned to a principal';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(request: ApiRequest): Promise<any[]> {
		const principalId = request.params?.['principalId'] as string;

		const roles = await this.auth.principalRolesRepo.find({
			where: { principal_id: principalId },
		});

		return roles;
	}
}
