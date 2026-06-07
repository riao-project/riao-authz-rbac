import { RiaoRouter } from '@riao/rest';
import { EvaluateAuthorizationEndpoint } from './evaluate-authorization-endpoint';

/**
 * Router for authorization evaluation endpoints
 */
export class EvaluateRouter extends RiaoRouter {
	public override path = '/evaluate';

	protected async routes(): Promise<any[]> {
		return [EvaluateAuthorizationEndpoint];
	}
}
