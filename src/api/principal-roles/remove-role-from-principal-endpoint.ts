import { RiaoDeleteEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { NotFoundError, BadRequestError, UnprocessableEntityError } from 'api-machine';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * DELETE /principals/:principalId/roles/:roleId - Remove role from principal
 */
export class RemoveRoleFromPrincipalEndpoint extends RiaoDeleteEndpoint<DatabaseRecordWithId> {
	public override path = '/:principalId/roles/:roleId';
	public override description = 'Remove an RBAC role from a principal';

	protected auth: RbacAuthorization;

	public override params = new ObjectValSan({
		schema: {
			principalId: new MinLengthValidator({ minLength: 1 }),
			roleId: new MinLengthValidator({ minLength: 1 }),
		},
	});
	public override paramsExample = {
		principalId: 'principal-123',
		roleId: 'role-123',
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
		this.container.registerInstance('repo', this.auth.principalRolesRepo);
		super.inject();
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
