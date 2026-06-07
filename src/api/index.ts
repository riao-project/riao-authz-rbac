/**
 * RBAC Authorization API Endpoints
 * Exports router and endpoint utilities for REST integration
 */

export { DefaultRbacAuthzRouter } from './router';

// Roles domain
export { CreateRoleEndpoint } from './roles/create-role-endpoint';
export { GetRolesEndpoint } from './roles/get-roles-endpoint';
export { GetRoleEndpoint } from './roles/get-role-endpoint';
export { UpdateRoleEndpoint } from './roles/update-role-endpoint';
export { DeleteRoleEndpoint } from './roles/delete-role-endpoint';
export { RolesRouter } from './roles/router';

// Permissions domain
export { CreatePermissionEndpoint } from './permissions/create-permission-endpoint';
export { GetPermissionsEndpoint } from './permissions/get-permissions-endpoint';
export { GetPermissionEndpoint } from './permissions/get-permission-endpoint';
export { UpdatePermissionEndpoint } from './permissions/update-permission-endpoint';
export { DeletePermissionEndpoint } from './permissions/delete-permission-endpoint';
export { PermissionsRouter } from './permissions/router';

// Role-Permissions domain
export { AddPermissionToRoleEndpoint } from './role-permissions/add-permission-to-role-endpoint';
export { RemovePermissionFromRoleEndpoint } from './role-permissions/remove-permission-from-role-endpoint';
export { GetRolePermissionsEndpoint } from './role-permissions/get-role-permissions-endpoint';
export { RolePermissionsRouter } from './role-permissions/router';

// Principal-Roles domain
export { AssignRoleToPrincipalEndpoint } from './principal-roles/assign-role-to-principal-endpoint';
export { RemoveRoleFromPrincipalEndpoint } from './principal-roles/remove-role-from-principal-endpoint';
export { GetPrincipalRolesEndpoint } from './principal-roles/get-principal-roles-endpoint';
export { PrincipalRolesRouter } from './principal-roles/router';

// Evaluate domain
export { EvaluateAuthorizationEndpoint } from './evaluate/evaluate-authorization-endpoint';
export { EvaluateRouter } from './evaluate/router';
export {
	RiaoRouter,
	RiaoEndpoint,
	RiaoCreateEndpoint,
	RiaoGetOneEndpoint,
	RiaoGetListEndpoint,
	RiaoUpdateEndpoint,
	RiaoDeleteEndpoint,
	DatabaseRecordWithId,
} from '@riao/rest';
