import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * POST /role-permissions - Add permission to role
 */
export class AddPermissionToRoleEndpoint extends RiaoCreateEndpoint<DatabaseRecordWithId> {
	public override path = '/';
	public override description = 'Add a permission to an RBAC role';

	protected auth: RbacAuthorization;

	public override body = new ObjectValSan({
		schema: {
			roleId: new MinLengthValidator({ minLength: 1 }),
			permissionId: new MinLengthValidator({ minLength: 1 }),
		},
	});

	public override bodyExample = {
		roleId: 'role-123',
		permissionId: 'perm-123',
	};

	public override inject() {
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', this.auth.rolePermissionsRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest): Promise<Partial<DatabaseRecordWithId>> {
		const { roleId, permissionId } = request.body as {
			roleId: string;
			permissionId: string;
		};

		await this.auth.addPermissionToRole({ roleId, permissionId });
		const assignment = await this.auth.rolePermissionsRepo.findOne({
			where: { role_id: roleId, permission_id: permissionId },
		});

		if (typeof assignment?.id !== 'string') {
			throw new Error('Permission assignment returned no string ID');
		}

		return { id: assignment.id };
	}
}
