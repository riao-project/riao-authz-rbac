import { RiaoUpdateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { NotFoundError, BadRequestError, UnprocessableEntityError } from 'api-machine';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * PUT /roles/:roleId - Update a role
 */
export class UpdateRoleEndpoint extends RiaoUpdateEndpoint<DatabaseRecordWithId> {
	public override path = '/:roleId';
	public override description = 'Update an RBAC role';

	protected auth: RbacAuthorization;

	public override params = new ObjectValSan({
		schema: { roleId: new MinLengthValidator({ minLength: 1 }) },
	});
	public override paramsExample = { roleId: 'role-123' };

	public override body = new ObjectValSan({
		schema: {
			name: new MinLengthValidator({
				minLength: 1, isOptional: true,
			}),
			description: new MinLengthValidator({
				minLength: 0, isOptional: true,
			}),
		},
	});

	public override bodyExample = {
		name: 'admin',
		description: 'Administrator role with full access',
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
		this.container.registerInstance('repo', this.auth.rolesRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest) {
		const roleId = request.params?.['roleId'] as string;

		const updates: any = {};
		if (request.body?.name) {
			updates.name = request.body.name;
		}

		if (request.body?.description) {
			updates.description = request.body.description;
		}

		await this.auth.rolesRepo.update({
			where: { id: roleId as any },
			set: updates,
		});

		return {};
	}
}
