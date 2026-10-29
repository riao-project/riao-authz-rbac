import { RiaoDeleteEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { NotFoundError, BadRequestError, UnprocessableEntityError } from 'api-machine';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * DELETE /principal-roles/:id - Deactivate a principal-role assignment
 */
export class RemoveRoleFromPrincipalEndpoint extends RiaoDeleteEndpoint<DatabaseRecordWithId> {
	public override path = '/:id';
	public override description = 'Deactivate an RBAC principal-role assignment';

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
		this.container.registerInstance('repo', this.auth.principalRolesRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest): Promise<Partial<DatabaseRecordWithId>> {
		const id = request.params['id'] as string;
		await this.findOneOr404(id);
		await this.auth.principalRolesRepo.update({
			where: { id },
			set: { deactivate_timestamp: new Date() },
		});

		return {};
	}
}
