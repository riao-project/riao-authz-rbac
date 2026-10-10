import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * POST /roles - Create a new role
 */
export class CreateRoleEndpoint extends RiaoCreateEndpoint<
 DatabaseRecordWithId
> {
	public override path = '/roles';
	public override description = 'Create a new RBAC role';

	protected auth: RbacAuthorization;

	public override bodyExample = {
		roleName: 'admin',
		description: 'Administrator role with full access',
	};

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(request: ApiRequest): Promise<Partial<DatabaseRecordWithId>> {
		const { roleName, description } = request.body as {
			roleName: string;
			description?: string;
		};

		const result = await this.auth.rolesRepo.insertOne({
			record: {
				name: roleName,
				description,
			},
		});

		return result as { id: string };
	}
}
