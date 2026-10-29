import { RiaoGetOneEndpoint } from '@riao/rest';
import { NotFoundError, BadRequestError, UnprocessableEntityError } from 'api-machine';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * GET /permissions/:permissionId - Get a specific permission
 */
export class GetPermissionEndpoint extends RiaoGetOneEndpoint<any> {
	public override path = '/:permissionId';
	public override description = 'Get a specific RBAC permission by ID';

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

	public override async handle(request: ApiRequest): Promise<any> {
		const permissionId = request.params?.['permissionId'] as string;

		const permission = await this.auth.permissionsRepo.findOne({
			where: { id: permissionId },
		});

		return permission;
	}
}
