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

### 2. Grant Permissions

Grant a permission to a principal by creating a role and assigning it:

```typescript
// Grant a single permission
await rbac.grantPermission({
	principalId,
	action: 'read',
	resource: 'documents'
});

// Grant an action-only permission (no specific resource)
await rbac.grantPermission({
	principalId,
	action: 'logout'
});
```

### 3. Check Authorization

Check if a principal is authorized for an action:

```typescript
// Check with a specific resource
const isAuthorized = await rbac.isAuthorized({
	principal,
	action: 'read',
	resource: 'documents'
});

// Check without a resource (for action-only permissions)
const canLogout = await rbac.isAuthorized({ principal, action: 'logout' });

// Full evaluation with metadata
const result = await rbac.evaluate({
	principal,
	action: 'write',
	resource: 'documents',
	metadata: { ip: '192.168.1.1' }
});

if (result.allowed) {
	console.log('Access granted');
} else {
	console.log('Access denied:', result.reason);
}
```

### 4. Revoke Permissions

Revoke a permission by deactivating the role assignment:

```typescript
await rbac.revokePermission({
	principalId,
	action: 'read'
});
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

##### `isAuthorized(context: { principal: Principal, action: string, resource?: string }): Promise<boolean>`

Convenience method that calls `evaluate()` and returns only the boolean result.

```typescript
if (await rbac.isAuthorized({ principal: user, action: 'delete', resource: 'users' })) {
	// User can delete users
}
```

##### `grantPermission(options: GrantPermissionOptions): Promise<void>`

Grants a permission to a principal by assigning a role.

**Options:**
- `principalId`: The principal ID to grant permission to
- `action`: The action name (e.g., "read", "write", "delete")
- `resource` (optional): The resource scope (e.g., "documents", "users")

**Behavior:**
1. Creates or reuses a role for the action
2. Creates or reuses a permission for the action and resource
3. Links the permission to the role (if not already linked)
4. Assigns the role to the principal (if not already assigned)

```typescript
// Grant "read" permission on "documents"
await rbac.grantPermission({
	principalId,
	action: 'read',
	resource: 'documents'
});

// Grant action-only "logout" permission
await rbac.grantPermission({
	principalId,
	action: 'logout'
});
```

**Note:** Idempotent - safe to call multiple times

##### `revokePermission(options: RevokePermissionOptions): Promise<void>`

Revokes a permission from a principal by deactivating the role assignment.

**Options:**
- `principalId`: The principal ID to revoke permission from
- `action`: The action name to revoke

```typescript
await rbac.revokePermission({
	principalId,
	action: 'delete'
});
```

**Behavior:**
1. Finds the role for the action
2. Sets `deactivate_timestamp` on the principal-role assignment
3. Does not delete data; allows for audit trails and reactivation

**Note:** Deactivation is soft-delete; the principal can be re-granted the permission later

### Repository Access

The RBAC instance exposes public repositories for direct database access:

```typescript
const rbac = new RbacAuthorization({ db });

// Access repositories directly if needed
rbac.rolesRepo							// QueryRepository<RbacRole>
rbac.permissionsRepo				// QueryRepository<RbacPermission>
rbac.rolePermissionsRepo		// QueryRepository<RbacRolePermission>
rbac.principalRolesRepo		 // QueryRepository<RbacPrincipalRole>
```

## Usage Examples

### Basic Permission Check

```typescript
const rbac = new RbacAuthorization({ db });

// Check if user can read documents
if (await rbac.isAuthorized({ principal: user, action: 'read', resource: 'documents' })) {
	// Allow access
}
```

### Multiple Roles

A principal can have multiple roles with different permissions:

```typescript
// Principal has both "editor" and "reviewer" roles
await rbac.grantPermission({ principalId: userId, action: 'write', resource: 'articles' });	// editor
await rbac.grantPermission({ principalId: userId, action: 'approve' });						 // reviewer

// Has access through either role
await rbac.isAuthorized({ principal: user, action: 'write', resource: 'articles' });	// true
await rbac.isAuthorized({ principal: user, action: 'approve' });						 // true
```

### Hierarchical Permissions

Implement permission hierarchies using naming conventions:

```typescript
// Define related permissions
await rbac.grantPermission({ principalId: userId, action: 'read', resource: 'documents' });
await rbac.grantPermission({ principalId: userId, action: 'read', resource: 'reports' });
await rbac.grantPermission({ principalId: userId, action: 'read', resource: 'analytics' });

// Check specific permissions
await rbac.isAuthorized({ principal: user, action: 'read', resource: 'documents' });	// true
```

### Temporary Access

Grant access temporarily and revoke it later:

```typescript
// Grant temporary access
await rbac.grantPermission({ principalId: userId, action: 'export', resource: 'data' });

// Later, revoke the access
await rbac.revokePermission({ principalId: userId, action: 'export' });
```

### Action-Only Permissions

For permissions that don't require a resource scope:

```typescript
// Grant action-only permission
await rbac.grantPermission({ principalId: userId, action: 'logout' });
await rbac.grantPermission({ principalId: userId, action: 'change-password' });
await rbac.grantPermission({ principalId: userId, action: 'view-profile' });

// Check authorization
await rbac.isAuthorized({ principal: user, action: 'logout' });							// true
await rbac.isAuthorized({ principal: user, action: 'logout', resource: 'resource' });	// true (null resource matches any)
```

## Contributing & Development

See [contributing.md](docs/contributing/contributing.md) for information on how to develop or contribute to this project!

## License

See [LICENSE.md](LICENSE.md)
