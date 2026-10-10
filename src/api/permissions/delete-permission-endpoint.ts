import { RiaoDeleteEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * DELETE /permissions/:permissionId - Delete a permission
 */
export class DeletePermissionEndpoint extends RiaoDeleteEndpoint<
 DatabaseRecordWithId
> {
	public override path = '/permissions/:permissionId';
	public override description = 'Delete an RBAC permission';

	protected auth: RbacAuthorization;

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(request: ApiRequest) {
		const permissionId = request.params?.['permissionId'] as string;

		await this.auth.permissionsRepo.delete({
			where: { id: permissionId },
		});

		return {};
	}
}
