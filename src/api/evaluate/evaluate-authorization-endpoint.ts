import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import {
	ApiRequest,
	AuthorizationResult,
	BadRequestError,
	UnauthorizedError,
} from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';

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
		const principal = request.principal;
		if (!principal) {
			this.logAuthorization(
				'warn', 'rbac.evaluate.missing-principal', request
			);
			throw new UnauthorizedError(
				'An authenticated principal is required'
			);
		}

		const action: unknown = request.body?.action;
		const resource: unknown = request.body?.resource;

		if (
			typeof action !== 'string' ||
			!action.trim() ||
			(resource !== undefined &&
				(typeof resource !== 'string' || !resource.trim()))
		) {
			this.logAuthorization(
				'warn', 'rbac.evaluate.invalid-input', request
			);
			throw new BadRequestError(
				'Action must be a non-empty string; resource, if provided, ' +
				'must be a non-empty string'
			);
		}

		try {
			const result = await this.auth.evaluate({
				principal,
				action,
				resource,
			});

			if (!result) {
				throw new Error(
					'Authorization evaluation returned no result'
				);
			}

			this.logAuthorization(
				'info', 'rbac.evaluate.result', request, {
					action,
					resource,
					allowed: result.allowed,
				}
			);

			return result;
		}
		catch (error) {
			this.logAuthorization(
				'error', 'rbac.evaluate.error', request,
				{ action, resource, error }
			);

			throw error;
		}
	}
}
