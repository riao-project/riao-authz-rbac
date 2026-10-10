import { RiaoDeleteEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * DELETE /principals/:principalId/roles/:roleId - Remove role from principal
 */
export class RemoveRoleFromPrincipalEndpoint extends RiaoDeleteEndpoint<
 DatabaseRecordWithId
> {
	public override path = '/principals/:principalId/roles/:roleId';
	public override description = 'Remove an RBAC role from a principal';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(request: ApiRequest): Promise<Partial<DatabaseRecordWithId>> {
		const principalId = request.params?.['principalId'] as string;
		const roleId = request.params?.['roleId'] as string;

		await this.auth.principalRolesRepo.delete({
			where: { principal_id: principalId, role_id: roleId },
		});

		return {};
	}
}
