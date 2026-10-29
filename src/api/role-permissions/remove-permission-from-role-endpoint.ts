import { RiaoDeleteEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { NotFoundError, BadRequestError, UnprocessableEntityError } from 'api-machine';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * DELETE /roles/:roleId/permissions/:permissionId - Remove permission from role
 */
export class RemovePermissionFromRoleEndpoint extends RiaoDeleteEndpoint<DatabaseRecordWithId> {
	public override path = '/:roleId/permissions/:permissionId';
	public override description = 'Remove a permission from an RBAC role';

	protected auth: RbacAuthorization;

	public override params = new ObjectValSan({
		schema: {
			roleId: new MinLengthValidator({ minLength: 1 }),
			permissionId: new MinLengthValidator({ minLength: 1 }),
		},
	});
	public override paramsExample = {
		roleId: 'role-123',
		permissionId: 'perm-123',
	};

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
		this.container.registerInstance('repo', this.auth.rolePermissionsRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest): Promise<Partial<DatabaseRecordWithId>> {
		const roleId = request.params?.['roleId'] as string;
		const permissionId = request.params?.['permissionId'] as string;

		await this.auth.rolePermissionsRepo.delete({
			where: {
				role_id: roleId,
				permission_id: permissionId,
			},
		});

		return {};
	}
}
