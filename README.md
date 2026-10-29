# @riao/authz-rbac

A Role-Based Access Control (RBAC) Authorization Driver for the Riao Identity & Access Management (IAM) system.

## Overview

`@riao/authz-rbac` provides a complete RBAC implementation for the Riao IAM framework. RBAC is a widely-used authorization model that grants permissions to roles, which are then assigned to principals (users, applications, etc.).

### RBAC Model

The RBAC authorization model follows this hierarchy:

```
Principal → Roles → Permissions
```

**How it works:**
- **Principals** (users, applications, services) are assigned **Roles**
- **Roles** are granted **Permissions**
- A **Permission** is an action (e.g., "read", "write", "delete") optionally scoped to a resource (e.g., "documents", "users")
- Authorization is granted when a principal has an active role that contains the required permission

### Key Features

- ✅ Full RBAC authorization model implementation
- ✅ Action-only and resource-specific permissions
- ✅ Role activation/deactivation
- ✅ Multiple roles per principal support
- ✅ Permission inheritance through roles
- ✅ Comprehensive test coverage
- ✅ TypeScript-first development

## Installation

```bash
npm install @riao/authz-rbac @riao/iam @riao/dbal
npm install --save-dev @riao/cli
```

```bash
npx riao migration:create import-rbac-tables
```

`database/main/migrations/123456789-import-rbac-tables.ts`:
```typescript
import { AuthzRbacMigrations } from '@riao/authz-rbac/authz-rbac-migrations';

export default AuthzRbacMigrations;
```

## Quick Start

### 1. Setup

```typescript
import { Database } from '@riao/dbal';
import { RbacAuthorization } from '@riao/authz-rbac';

const db = new Database(/* ... */);
const rbac = new RbacAuthorization({ db });
```

## 2. Define roles & permissions

```typescript
const roleId = await rbac.role({ name: 'administrator' });
const permissionId = await rbac.permission({
	action: 'manage',
	resource: 'documents'
});
await rbac.addPermissionToRole({ roleId, permissionId });
```

These helpers reuse existing records if they already exist. `role()` and `permission()` leave existing descriptions and role activation unchanged.

### 2. Grant Roles & Permissions

Assign a role to a principal:

```typescript
await rbac.assignRole({ principalId, roleId });
```

Define a named role, add permissions to it, then assign that role:

```typescript
const roleId = await rbac.role({ name: 'document-reader' });
const permissionId = await rbac.permission({
	action: 'read',
	resource: 'documents'
});
await rbac.addPermissionToRole({ roleId, permissionId });
await rbac.assignRole({ principalId, roleId });
```

### 3. Check Authorization

Check if a principal is authorized for an action:

Both `evaluate()` and `isAuthorized()` accept a trusted ID-only subject
(`{ id: string }`) or a full IAM principal. In an API, use the authenticated
request principal, never a body-supplied principal ID. RBAC resources must be
non-empty strings when supplied; object-resource policies require a different
authorization implementation.

Policy denials return `{ allowed: false, reason }`. Database and evaluation
failures reject unchanged and are logged by the API boundary, not converted
into denials or exception-bearing reasons. Protected HTTP routes distinguish
401 (no principal), 403 (policy denial), and 500 (unexpected service failure).

See the [compiled server example](examples/index.ts)

```typescript
const server = new RbacExampleServer(db, async (token) => {
	const payload = await oauth2.verifyAccessToken(token);

	if (!payload) {
		return false;
	}

	return (await oauth2.findActivePrincipal({
		where: { id: payload.principal_id },
	})) ?? false;
});

await server.start();
```

The authorizer uses `request.principal`, not an identity submitted in the body.

The database-free [example contract tests](test/spec/example-contract.spec.ts) verify public opt-out, authentication-before-policy ordering, and trusted ID-only role lookup through this server. After building, run:

```sh
npm run test:run -- dist/test/spec/example-contract.spec.js
```

```typescript
// Check with a specific resource
const result = await rbac.evaluate({
	principal,
	action: 'read',
	resource: 'documents'
});

// Check without a resource (for action-only permissions)
const logoutResult = await rbac.evaluate({ principal, action: 'logout' });

// Full evaluation with metadata
const writeResult = await rbac.evaluate({
	principal,
	action: 'write',
	resource: 'documents',
	metadata: { ip: '192.168.1.1' }
});

if (writeResult.allowed) {
	console.log('Access granted');
} else {
	console.log('Access denied:', writeResult.reason);
}
```

### 4. Revoke Role Assignments

Permissions belong to roles, so remove access by deactivating the principal's role assignment through the principal-role API.

```typescript
const assignment = await rbac.principalRolesRepo.findOne({
	where: { principal_id: principalId, role_id: roleId }
});
if (assignment) {
	await rbac.principalRolesRepo.update({
		where: { id: assignment.id },
		set: { deactivate_timestamp: new Date() }
	});
}
```

## Core Concepts

### Roles

Roles are containers for permissions. They allow grouping related permissions and assigning them to principals in bulk.

```typescript
// Interfaces
interface RbacRole {
	id: DatabaseRecordId;
	name: string;
	description?: string;
	create_timestamp: Date;
	deactivate_timestamp?: Date;
}
```

**Properties:**
- `name`: Unique identifier for the role (e.g., "editor", "viewer", "admin")
- `description`: Optional description of the role's purpose
- `deactivate_timestamp`: When set, indicates the role is inactive

### Permissions

Permissions represent what actions can be performed, optionally on specific resources.

```typescript
interface RbacPermission {
	id: DatabaseRecordId;
	action: string;
	resource: string | null;
	description?: string;
	create_timestamp: Date;
}
```

**Properties:**
- `action`: The action being performed (e.g., "read", "write", "delete")
- `resource`: Optional resource identifier (e.g., "documents", "users"). When `null`, the permission applies to the action regardless of resource

**Examples:**
- `action: "read"`, `resource: "documents"` → Can read documents
- `action: "logout"`, `resource: null` → Can logout (no resource)

### Role-Permission Assignment

Links roles to permissions. A role can have multiple permissions, and a permission can be assigned to multiple roles.

```typescript
interface RbacRolePermission {
	id: DatabaseRecordId;
	role_id: DatabaseRecordId;
	permission_id: DatabaseRecordId;
	create_timestamp: Date;
}
```

### Principal-Role Assignment

Links principals to roles. A principal can have multiple roles, and roles can be deactivated without deletion.

```typescript
interface RbacPrincipalRole {
	id: DatabaseRecordId;
	principal_id: DatabaseRecordId;
	role_id: DatabaseRecordId;
	create_timestamp: Date;
	deactivate_timestamp?: Date;
}
```

## API Reference

### RbacAuthorization Class

#### Constructor

```typescript
new RbacAuthorization(options: RbacAuthorizationOptions)
```

**Parameters:**
- `options.db`: Database instance for RBAC operations

#### Methods

##### `evaluate(context: AuthorizationContext): Promise<AuthorizationResult>`

Evaluates whether a principal is authorized for an action.

```typescript
const result = await rbac.evaluate({
	principal: user,
	action: 'read',
	resource: 'documents'
});

// Returns: { allowed: true } or { allowed: false, reason: "..." }
```

**Evaluation Logic:**
1. Fetch all active roles for the principal
2. Get all permissions assigned to those roles
3. Match permissions by action and resource
4. Return authorization result

**Permission Matching Rules:**
- If a resource is provided: Match permissions with the exact resource OR permissions with `resource: null`
- If no resource is provided: Only match permissions with `resource: null`

##### `evaluate(context: AuthorizationContext): Promise<AuthorizationResult>`

Evaluates authorization for a principal, action, and optional resource.

```typescript
const result = await rbac.evaluate({
	principal: user,
	action: 'delete',
	resource: 'users'
});

if (result.allowed) {
	// User can delete users
}
```

##### `role(options): Promise<DatabaseRecordId>`

Creates or reuses a role by name.

##### `permission(options): Promise<DatabaseRecordId>`

Creates or reuses a permission by action and optional resource.

##### `addPermissionToRole(options): Promise<void>`

Links an existing permission to a role. Repeated links are ignored.

##### `assignRole(options): Promise<void>`

Assigns (or reactivates) an existing role to a principal.

### Repository Access

The RBAC instance exposes public repositories for direct database access:

```typescript
const rbac = new RbacAuthorization({ db });

// Access repositories directly if needed
rbac.rolesRepo				// QueryRepository<RbacRole>
rbac.permissionsRepo		// QueryRepository<RbacPermission>
rbac.rolePermissionsRepo	// QueryRepository<RbacRolePermission>
rbac.principalRolesRepo		// QueryRepository<RbacPrincipalRole>
```

## Usage Examples

### Basic Permission Check

```typescript
const rbac = new RbacAuthorization({ db });

// Check if user can read documents
const result = await rbac.evaluate({
	principal: user,
	action: 'read',
	resource: 'documents'
});

if (result.allowed) {
	// Allow access
}
```

### Multiple Roles

A principal can have multiple roles with different permissions:

```typescript
// Principal has both "editor" and "reviewer" roles
const editorId = await rbac.role({ name: 'editor' });
const writeArticlesId = await rbac.permission({
	action: 'write',
	resource: 'articles'
});
await rbac.addPermissionToRole({
	roleId: editorId, permissionId: writeArticlesId,
});
await rbac.assignRole({ principalId: userId, roleId: editorId });

const reviewerId = await rbac.role({ name: 'reviewer' });
const approveId = await rbac.permission({ action: 'approve' });
await rbac.addPermissionToRole({
	roleId: reviewerId, permissionId: approveId,
});
await rbac.assignRole({ principalId: userId, roleId: reviewerId });

// Has access through either role
const canWrite = await rbac.evaluate({
	principal: user,
	action: 'write',
	resource: 'articles'
});	// true
const canApprove = await rbac.evaluate({
	principal: user,
	action: 'approve'
});	// true
```

### Hierarchical Permissions

Implement permission hierarchies using naming conventions:

```typescript
// Group related permissions in a role
const readerId = await rbac.role({ name: 'analytics-reader' });
for (const resource of ['documents', 'reports', 'analytics']) {
	const permissionId = await rbac.permission({ action: 'read', resource });
	await rbac.addPermissionToRole({
		roleId: readerId, permissionId,
	});
}
await rbac.assignRole({ principalId: userId, roleId: readerId });

// Check specific permissions
const canReadDocs = await rbac.evaluate({ principal: user, action: 'read', resource: 'documents' });	// true
```

### Action-Only Permissions

For permissions that don't require a resource scope:

```typescript
// Group action-only permissions into a role
const accountUserId = await rbac.role({ name: 'account-user' });
for (const action of ['logout', 'change-password', 'view-profile']) {
	const permissionId = await rbac.permission({ action });
	await rbac.addPermissionToRole({
		roleId: accountUserId, permissionId,
	});
}
await rbac.assignRole({ principalId: userId, roleId: accountUserId });

// Check authorization
const canLogout = await rbac.evaluate({
	principal: user,
	action: 'logout'
});	// true
const canLogoutWithResource = await rbac.evaluate({
	principal: user,
	action: 'logout',
	resource: 'resource'
});	// true (null resource matches any)
```

## Contributing & Development

See [contributing.md](docs/contributing/contributing.md) for information on how to develop or contribute to this project!

## License

See [LICENSE.md](LICENSE.md)
