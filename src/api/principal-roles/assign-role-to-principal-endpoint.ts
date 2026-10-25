import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

/**
 * POST /principals/:principalId/roles - Assign role to principal
 */
export class AssignRoleToPrincipalEndpoint extends RiaoCreateEndpoint<
 DatabaseRecordWithId
> {
	public override path = '/principals/:principalId/roles';
	public override description = 'Assign an RBAC role to a principal';

	protected auth: RbacAuthorization;

	public override bodyExample = {
		roleId: 'role-123',
	};

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(request: ApiRequest): Promise<Partial<DatabaseRecordWithId>> {
		const principalId = request.params?.['principalId'] as string;
		const { roleId } = request.body as {
			roleId: string;
		};

		if (!this.auth) {
			throw new Error('Authentication handler not initialized');
		}

		const result = await this.auth.principalRolesRepo.insertOne({
			record: {
				principal_id: principalId,
				role_id: roleId,
			},
		});

		return {};
	}
}
