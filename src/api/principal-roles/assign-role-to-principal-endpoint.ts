import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { MinLengthValidator, ObjectValSan } from 'valsan';

/**
 * POST /principals/:principalId/roles - Assign role to principal
 */
export class AssignRoleToPrincipalEndpoint extends RiaoCreateEndpoint<DatabaseRecordWithId> {
	public override path = '/:principalId/roles';
	public override description = 'Assign an RBAC role to a principal';

	protected auth: RbacAuthorization;

	public override params = new ObjectValSan({
		schema: { principalId: new MinLengthValidator({ minLength: 1 }) },
	});
	public override paramsExample = { principalId: 'principal-123' };

	public override body = new ObjectValSan({
		schema: { roleId: new MinLengthValidator({ minLength: 1 }) },
	});

	public override bodyExample = {
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
