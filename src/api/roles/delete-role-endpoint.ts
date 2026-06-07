import { RiaoDeleteEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * DELETE /roles/:roleId - Delete a role
 */
export class DeleteRoleEndpoint extends RiaoDeleteEndpoint<DatabaseRecordWithId> {
	public override path = '/roles/:roleId';
	public override description = 'Delete an RBAC role';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>('auth');
	}

	public override async handle(
		request: ApiRequest,
		response: ApiResponse,
		next: ApiNextFunction
	): Promise<Partial<DatabaseRecordWithId>> {
		const roleId = request.params?.roleId as string;

		await this.auth.rolesRepo.delete({
			where: { id: roleId },
		});

		return {};
	}
}
