import { RiaoGetOneEndpoint } from '@riao/rest';
import { NotFoundError, BadRequestError, UnprocessableEntityError } from 'api-machine';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * GET /roles/:roleId - Get a specific role
 */
export class GetRoleEndpoint extends RiaoGetOneEndpoint<any> {
	public override path = '/:roleId';
	public override description = 'Get a specific RBAC role by ID';

	protected auth: RbacAuthorization;

	public override params = new ObjectValSan({
		schema: { roleId: new MinLengthValidator({ minLength: 1 }) },
	});
	public override paramsExample = { roleId: 'role-123' };

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
		this.container.registerInstance('repo', this.auth.rolesRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest): Promise<any> {
		const roleId = request.params?.['roleId'] as string;

		const role = await this.auth.rolesRepo.findOne({
			where: { id: roleId },
		});

		return role;
	}
}
