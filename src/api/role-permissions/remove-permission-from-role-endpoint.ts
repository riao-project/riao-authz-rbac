import { RiaoDeleteEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { NotFoundError, BadRequestError, UnprocessableEntityError } from 'api-machine';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * DELETE /role-permissions/:id - Delete a role-permission assignment
 */
export class RemovePermissionFromRoleEndpoint extends RiaoDeleteEndpoint<DatabaseRecordWithId> {
	public override path = '/:id';
	public override description = 'Remove a permission from an RBAC role';

	protected auth: RbacAuthorization;

	public override params = new ObjectValSan({
		schema: {
			id: new MinLengthValidator({ minLength: 1 }),
		},
	});
	public override paramsExample = {
		id: 'assignment-123',
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
		const id = request.params['id'] as string;
		await this.findOneOr404(id);
		await this.auth.rolePermissionsRepo.delete({
			where: { id },
		});

		return {};
	}
}
