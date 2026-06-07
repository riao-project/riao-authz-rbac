import { RiaoUpdateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * PUT /roles/:roleId - Update a role
 */
export class UpdateRoleEndpoint extends RiaoUpdateEndpoint<DatabaseRecordWithId> {
	public override path = '/roles/:roleId';
	public override description = 'Update an RBAC role';

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
	) {
		const roleId = request.params?.roleId as string;

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
