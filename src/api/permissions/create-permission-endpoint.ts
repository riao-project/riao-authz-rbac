import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * POST /permissions - Create a new permission
 */
export class CreatePermissionEndpoint extends RiaoCreateEndpoint<DatabaseRecordWithId> {
	public override path = '/';
	public override description = 'Create a new RBAC permission';

	protected auth: RbacAuthorization;

	public override body = new ObjectValSan({
		schema: {
			action: new MinLengthValidator({ minLength: 1 }),
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

	public override inject() {
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', this.auth.permissionsRepo);
		super.inject();
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
