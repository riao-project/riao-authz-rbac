import { RiaoUpdateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * PUT /permissions/:permissionId - Update a permission
 */
export class UpdatePermissionEndpoint extends RiaoUpdateEndpoint<DatabaseRecordWithId> {
	public override path = '/permissions/:permissionId';
	public override description = 'Update an RBAC permission';

	protected auth: RbacAuthorization;

	public override bodyExample = {
		action: 'read',
		resource: 'users',
		description: 'Read users',
	};

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>('auth');
	}

	public override async handle(
		request: ApiRequest,
		response: ApiResponse,
		next: ApiNextFunction
	): Promise<Partial<DatabaseRecordWithId>> {
		const permissionId = request.params?.permissionId as string;

		const updates: any = {};
		if (request.body?.action) {
			updates.action = request.body.action;
		}

		if (request.body?.resource) {
			updates.resource = request.body.resource;
		}

		if (request.body?.description) {
			updates.description = request.body.description;
		}

		await this.auth.permissionsRepo.update({
			where: { id: permissionId },
			set: updates,
		});

		return {};
	}
}
