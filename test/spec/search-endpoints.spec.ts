import 'jasmine';
import { ApiRequest, UnprocessableEntityError } from 'api-machine';
import { EndpointMethod } from 'api-machine/router/endpoint';
import { OasEndpointConverter } from 'api-machine/oas/oas-endpoint-converter';
import { RiaoSearchEndpoint } from '@riao/rest';
import { searchValidators } from '@riao/rest/endpoints/search-endpoint';
import {
	SearchRolesEndpoint,
	SearchPermissionsEndpoint,
	SearchRolePermissionsEndpoint,
	SearchPrincipalRolesEndpoint,
} from '../../src';

describe('RBAC search endpoint contracts', () => {
	for (const endpoint of [
		new SearchRolesEndpoint(),
		new SearchPermissionsEndpoint(),
		new SearchRolePermissionsEndpoint(),
		new SearchPrincipalRolesEndpoint(),
	]) {
		describe(endpoint.constructor.name, () => {
			it('uses the standard Riao search contract', async () => {
				expect(endpoint instanceof RiaoSearchEndpoint).toBeTrue();
				expect(endpoint.path).toBe('/search');
				expect(endpoint.method).toBe(EndpointMethod.POST);
				expect(endpoint.statusCode).toBe(200);
				expect(Object.keys(endpoint.body.schema).sort())
					.toEqual(Object.keys(searchValidators).sort());
				expect(Object.keys(endpoint.response.schema).sort())
					.toEqual(['count', 'records']);
				for (const body of [endpoint.bodyExample, {}]) {
					await expectAsync(endpoint.checkRequest({
						body, params: {}, query: {},
					} as ApiRequest)).toBeResolved();
				}
			});

			it('rejects malformed search bodies', async () => {
				for (const body of [
					{ limit: 'invalid' },
					{ columns: [{}] },
					{ where: [{ column: 'id', operator: 'INVALID' }] },
					{ order: [{ column: 'id', direction: 'INVALID' }] },
				]) {
					await expectAsync(endpoint.checkRequest({
						body, params: {}, query: {},
					} as ApiRequest))
						.toBeRejectedWithError(UnprocessableEntityError);
				}
			});

			it('includes search schemas in generated OpenAPI', () => {
				const path = new OasEndpointConverter()
					.getOpenApiPath(endpoint);
				expect(path.post?.requestBody).toBeDefined();
				expect(path.post?.responses?.['200']).toBeDefined();
				expect(path.post?.responses?.['422']).toBeDefined();
			});
		});
	}
});
