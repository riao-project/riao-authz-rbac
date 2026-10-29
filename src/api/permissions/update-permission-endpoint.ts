import { RiaoUpdateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { NotFoundError, BadRequestError, UnprocessableEntityError } from 'api-machine';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * PUT /permissions/:permissionId - Update a permission
 */
export class UpdatePermissionEndpoint extends RiaoUpdateEndpoint<DatabaseRecordWithId> {
	public override path = '/:permissionId';
	public override description = 'Update an RBAC permission';

	protected auth: RbacAuthorization;

	public override params = new ObjectValSan({
		schema: { permissionId: new MinLengthValidator({ minLength: 1 }) },
	});
	public override paramsExample = { permissionId: 'perm-123' };

	public override body = new ObjectValSan({
		schema: {
			action: new MinLengthValidator({
				minLength: 1, isOptional: true,
			}),
			resource: new MinLengthValidator({
				minLength: 1, isOptional: true,
			}),
			description: new MinLengthValidator({
				minLength: 0, isOptional: true,
			}),
		},
	});

	public override bodyExample = {
		action: 'read',
		resource: 'users',
		description: 'Read users',
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
		this.container.registerInstance('repo', this.auth.permissionsRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest): Promise<Partial<DatabaseRecordWithId>> {
		const permissionId = request.params?.['permissionId'] as string;

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
