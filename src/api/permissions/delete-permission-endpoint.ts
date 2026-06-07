import { RiaoDeleteEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * DELETE /permissions/:permissionId - Delete a permission
 */
export class DeletePermissionEndpoint extends RiaoDeleteEndpoint<DatabaseRecordWithId> {
	public override path = '/permissions/:permissionId';
	public override description = 'Delete an RBAC permission';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>('auth');
	}

	public override async handle(
		request: ApiRequest,
		response: ApiResponse,
		next: ApiNextFunction
	) {
		const permissionId = request.params?.permissionId as string;

		await this.auth.permissionsRepo.delete({
			where: { id: permissionId },
		});

		return {};
	}
}
