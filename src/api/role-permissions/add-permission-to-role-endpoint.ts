import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * POST /roles/:roleId/permissions - Add permission to role
 */
export class AddPermissionToRoleEndpoint extends RiaoCreateEndpoint<DatabaseRecordWithId> {
	public override path = '/roles/:roleId/permissions';
	public override description = 'Add a permission to an RBAC role';

	protected auth: RbacAuthorization;

	public override bodyExample = {
		permissionId: 'perm-123',
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
		const roleId = request.params?.roleId as string;
		const { permissionId } = request.body as {
			permissionId: string;
		};

		const result = await this.auth.rolePermissionsRepo.insertOne({
			record: {
				role_id: roleId,
				permission_id: permissionId,
			},
		});

		return result as { id: string };
	}
}
