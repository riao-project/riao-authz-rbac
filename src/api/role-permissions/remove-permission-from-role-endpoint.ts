import { RiaoDeleteEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * DELETE /roles/:roleId/permissions/:permissionId - Remove permission from role
 */
export class RemovePermissionFromRoleEndpoint extends RiaoDeleteEndpoint<DatabaseRecordWithId> {
	public override path = '/roles/:roleId/permissions/:permissionId';
	public override description = 'Remove a permission from an RBAC role';

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
		const permissionId = request.params?.permissionId as string;

		await this.auth.rolePermissionsRepo.delete({
			where: {
				role_id: roleId,
				permission_id: permissionId,
			},
		});

		return {};
	}
}
