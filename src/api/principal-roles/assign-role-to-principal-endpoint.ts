import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * POST /principal-roles - Assign role to principal
 */
export class AssignRoleToPrincipalEndpoint extends RiaoCreateEndpoint<DatabaseRecordWithId> {
	public override path = '/';
	public override description = 'Assign an RBAC role to a principal';

	protected auth: RbacAuthorization;

	public override body = new ObjectValSan({
		schema: {
			principalId: new MinLengthValidator({ minLength: 1 }),
			roleId: new MinLengthValidator({ minLength: 1 }),
		},
	});

	public override bodyExample = {
		principalId: 'principal-123',
		roleId: 'role-123',
	};

	public override inject() {
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
		this.container.registerInstance('repo', this.auth.principalRolesRepo);
		super.inject();
	}

	public override async handle(request: ApiRequest): Promise<Partial<DatabaseRecordWithId>> {
		const { principalId, roleId } = request.body as {
			principalId: string;
			roleId: string;
		};

		await this.auth.assignRole({ principalId, roleId });
		const assignment = await this.auth.principalRolesRepo.findOne({
			where: { principal_id: principalId, role_id: roleId },
		});
		if (typeof assignment?.id !== 'string') {
			throw new Error('Role assignment returned no string ID');
		}

		return { id: assignment.id };
	}
}
