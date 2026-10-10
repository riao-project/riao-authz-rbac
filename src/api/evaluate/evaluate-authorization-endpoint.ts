import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { UnauthorizedError } from 'api-machine';
import { Principal } from '@riao/iam/auth';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { AuthorizationResult } from 'api-machine';

/**
 * POST /evaluate - Check if principal can perform action
 */
export class EvaluateAuthorizationEndpoint extends RiaoCreateEndpoint<
	DatabaseRecordWithId
> {
	public override path = '/evaluate';
	public override description =
		'Evaluate if a principal can perform an action';

	protected auth: RbacAuthorization;

	public override bodyExample = {
		action: 'read',
		resource: 'documents',
	};

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(
		request: ApiRequest
	): Promise<AuthorizationResult> {
		const principal = (
			request as ApiRequest & { principal?: Principal }
		).principal;
		if (!principal) {
			throw new UnauthorizedError(
				'An authenticated principal is required'
			);
		}

		const action = request.body?.action as string;
		const resource = request.body?.resource as string;

		try {
			const result = await this.auth.evaluate?.({
				principal,
				action: action as string,
				resource: resource,
			});

			if (!result) {
				throw new Error(
					'Authorization evaluation returned no result'
				);
			}

			return result;
		}
		catch (error) {
			const message =
				error instanceof Error
					? error.message
					: 'Authorization evaluation failed';

			throw new Error(message);
		}
	}
}
