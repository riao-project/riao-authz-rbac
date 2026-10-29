import { RiaoDeleteEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { NotFoundError, BadRequestError, UnprocessableEntityError } from 'api-machine';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * DELETE /permissions/:permissionId - Delete a permission
 */
export class DeletePermissionEndpoint extends RiaoDeleteEndpoint<DatabaseRecordWithId> {
	public override path = '/:permissionId';
	public override description = 'Delete an RBAC permission';

	protected auth: RbacAuthorization;

	public override params = new ObjectValSan({
		schema: { permissionId: new MinLengthValidator({ minLength: 1 }) },
	});
	public override paramsExample = { permissionId: 'perm-123' };

	public override getErrors() {
		return {
			...super.getErrors(),
			parse: new BadRequestError(),
			validation: new UnprocessableEntityError(),
			not_found: new NotFoundError('Record not found'),
		};
	}

	public override inject() {
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', this.auth.permissionsRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest) {
		const permissionId = request.params?.['permissionId'] as string;

		await this.auth.permissionsRepo.delete({
			where: { id: permissionId },
		});

		return {};
	}
}
