import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * POST /permissions - Create a new permission
 */
export class CreatePermissionEndpoint extends RiaoCreateEndpoint<
	DatabaseRecordWithId
> {
	public override path = '/permissions';
	public override description = 'Create a new RBAC permission';

	protected auth: RbacAuthorization;

	public override bodyExample = {
		permissionName: 'read_users',
		action: 'read',
		resource: 'users',
	};

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(
		request: ApiRequest
	): Promise<Partial<DatabaseRecordWithId>> {
		const result = await this.auth.permissionsRepo.insertOne({
			record: {
				action: request.body?.action,
				resource: request.body?.resource,
				description: request.body?.description,
			},
		});

		return result as { id: string };
	}
}
