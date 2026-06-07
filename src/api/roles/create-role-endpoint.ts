import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * POST /roles - Create a new role
 */
export class CreateRoleEndpoint extends RiaoCreateEndpoint<DatabaseRecordWithId> {
	public override path = '/roles';
	public override description = 'Create a new RBAC role';

	protected auth: RbacAuthorization;

	public override bodyExample = {
		roleName: 'admin',
		description: 'Administrator role with full access',
	};

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>('auth');
	}

	public override async handle(
		request: ApiRequest,
		response: ApiResponse,
		next: ApiNextFunction
	): Promise<Partial<DatabaseRecordWithId>> {
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
