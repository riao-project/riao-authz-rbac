import 'jasmine';
import {
	ApiRequest, BaseApiEndpoint, UnprocessableEntityError,
} from 'api-machine';
import { OasEndpointConverter } from 'api-machine/oas/oas-endpoint-converter';
import {
	OasEndpointComponentConverter,
} from 'api-machine/oas/oas-endpoint-component-converter';
import {
	CreateRoleEndpoint,
	GetRolesEndpoint,
	GetRoleEndpoint,
	UpdateRoleEndpoint,
	DeleteRoleEndpoint,
	CreatePermissionEndpoint,
	GetPermissionsEndpoint,
	GetPermissionEndpoint,
	UpdatePermissionEndpoint,
	DeletePermissionEndpoint,
	AddPermissionToRoleEndpoint,
	RemovePermissionFromRoleEndpoint,
	GetRolePermissionsEndpoint,
	AssignRoleToPrincipalEndpoint,
	RemoveRoleFromPrincipalEndpoint,
	GetPrincipalRolesEndpoint,
	EvaluateAuthorizationEndpoint,
} from '../../src/api';

interface EndpointContract {
	endpoint: BaseApiEndpoint;
	body?: string[];
	query?: string[];
}

describe('RBAC endpoint request schemas', () => {
	const listFields = ['limit', 'offset', 'orderBy', 'orderDirection'];
	const contracts: EndpointContract[] = [
		{
			endpoint: new CreateRoleEndpoint(),
			body: ['roleName', 'description'],
		},
		{ endpoint: new GetRolesEndpoint(), query: listFields },
		{ endpoint: new GetRoleEndpoint() },
		{
			endpoint: new UpdateRoleEndpoint(),
			body: ['name', 'description'],
		},
		{ endpoint: new DeleteRoleEndpoint() },
		{
			endpoint: new CreatePermissionEndpoint(),
			body: ['action', 'resource', 'description'],
		},
		{ endpoint: new GetPermissionsEndpoint(), query: listFields },
		{ endpoint: new GetPermissionEndpoint() },
		{
			endpoint: new UpdatePermissionEndpoint(),
			body: ['action', 'resource', 'description'],
		},
		{ endpoint: new DeletePermissionEndpoint() },
		{
			endpoint: new AddPermissionToRoleEndpoint(),
			body: ['roleId', 'permissionId'],
		},
		{ endpoint: new RemovePermissionFromRoleEndpoint() },
		{ endpoint: new GetRolePermissionsEndpoint(), query: listFields },
		{
			endpoint: new AssignRoleToPrincipalEndpoint(),
			body: ['principalId', 'roleId'],
		},
		{ endpoint: new RemoveRoleFromPrincipalEndpoint() },
		{ endpoint: new GetPrincipalRolesEndpoint(), query: listFields },
		{
			endpoint: new EvaluateAuthorizationEndpoint(),
			body: ['action', 'resource'],
		},
	];

	for (const { endpoint, body, query } of contracts) {
		describe(endpoint.constructor.name, () => {
			const params = Array.from(
				endpoint.path.matchAll(/:([A-Za-z0-9_]+)/g),
				(match) => match[1]
			);
			const fields = {
				body, params: params.length ? params : undefined, query,
			};

			for (const part of ['body', 'params', 'query'] as const) {
				it(`declares matching ${part} schema and example`, async () => {
					const schema = endpoint[part];
					const example: Record<string, unknown> | undefined =
						endpoint[`${part}Example`];
					const expected = fields[part];

					if (!expected) {
						expect(schema).toBeUndefined();
						expect(example).toBeUndefined();
						return;
					}

					expect(Object.hasOwn(endpoint, part)).toBeTrue();
					expect(Object.hasOwn(endpoint, `${part}Example`))
						.toBeTrue();
					expect(schema).toBeDefined();
					expect(example).toBeDefined();
					if (!schema || !example) {
						return;
					}
					expect(Object.keys(schema.schema).sort())
						.toEqual([...expected].sort());
					expect(Object.keys(example).sort())
						.toEqual([...expected].sort());
					expect((await schema.run(example)).success).toBeTrue();

					for (const field of expected) {
						const invalid = { ...example, [field]: {} };
						expect((await schema.run(invalid)).success)
							.withContext(`${part}.${field} must reject objects`)
							.toBeFalse();
						const missing = { ...example };
						delete missing[field];
						const options = schema.schema[field].options;
						const optional =
							options.isUndefinable ??
							options.isOptional ?? false;
						expect((await schema.run(missing)).success)
							.withContext(`${part}.${field} requiredness`)
							.toBe(optional);
					}
				});
			}

			it('validates its full example through the request boundary',
				async () => {
					const request = {
						body: endpoint.bodyExample,
						params: endpoint.paramsExample ?? {},
						query: endpoint.queryExample ?? {},
					} as ApiRequest;
					await expectAsync(endpoint.checkRequest(request))
						.toBeResolved();
				});

			it('includes schemas and examples in generated OpenAPI', () => {
				const path = new OasEndpointConverter()
					.getOpenApiPath(endpoint);
				const operation = path[endpoint.method];
				expect(operation).toBeDefined();
				expect(operation?.responses?.['422']).toBeDefined();
				expect(Boolean(operation?.requestBody)).toBe(Boolean(body));
				const components = new OasEndpointComponentConverter()
					.getSchemas(endpoint);
				if (body) {
					const schema = components[`${endpoint.name}Body`];
					expect(schema.example).toEqual(endpoint.bodyExample);
					expect(Object.keys(schema.properties ?? {}).sort())
						.toEqual([...body].sort());
				}
				for (const parameter of operation?.parameters ?? []) {
					if ('$ref' in parameter) {
						fail('Expected an inline request parameter');
						continue;
					}
					const example = parameter.in === 'path'
						? endpoint.paramsExample : endpoint.queryExample;
					expect(parameter.example).toEqual(example[parameter.name]);
				}
				expect(operation?.parameters?.length ?? 0)
					.toBe(params.length + (query?.length ?? 0));
			});
		});
	}

	it('accepts partial updates and optional creation fields', async () => {
		for (const [endpoint, body] of [
			[new CreateRoleEndpoint(), { roleName: 'admin' }],
			[new CreatePermissionEndpoint(), { action: 'logout' }],
			[
				new CreatePermissionEndpoint(),
				{ action: 'logout', resource: null },
			],
			[new UpdateRoleEndpoint(), {}],
			[new UpdateRoleEndpoint(), { description: 'Updated description' }],
			[new UpdatePermissionEndpoint(), {}],
			[new UpdatePermissionEndpoint(), { action: 'write' }],
		] as const) {
			expect((await endpoint.body.run(body)).success).toBeTrue();
		}
	});

	it('rejects invalid evaluation input at the request boundary', async () => {
		const endpoint = new EvaluateAuthorizationEndpoint();
		for (const body of [
			{}, { action: 1 }, { action: '' }, { action: ' ' },
			{ action: 'read', resource: null },
			{ action: 'read', resource: {} },
			{ action: 'read', resource: ' ' },
		]) {
			await expectAsync(endpoint.checkRequest({ body } as ApiRequest))
				.toBeRejectedWithError(UnprocessableEntityError);
		}
	});

	it('accepts ignored body principal IDs during evaluation', async () => {
		const endpoint = new EvaluateAuthorizationEndpoint();
		await expectAsync(endpoint.checkRequest({
			body: { action: 'read', principalId: 'untrusted-principal' },
		} as ApiRequest)).toBeResolved();
	});

	it('sanitizes list query strings and allows omitted list options',
		async () => {
			for (const { endpoint, query } of contracts) {
				if (!query) {
					continue;
				}
				const request = {} as ApiRequest;
				request.params = endpoint.paramsExample ?? {};
				request.query = {
					limit: '10', offset: '0',
					orderBy: 'id', orderDirection: 'asc',
				};
				await endpoint.checkRequest(request);
				const sanitized: Record<string, unknown> = request.query;
				expect(sanitized).toEqual({
					limit: 10, offset: 0, orderBy: 'id', orderDirection: 'ASC',
				});
				await expectAsync(endpoint.checkRequest({
					params: endpoint.paramsExample ?? {}, query: {},
				} as ApiRequest)).toBeResolved();
			}
		});
});
