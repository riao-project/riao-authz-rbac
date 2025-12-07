import { Migration, MigrationPackage } from '@riao/dbal';
/* eslint-disable max-len */
import { CreateRolesTableMigration } from './migrations/001-create-roles-table';
import { CreatePermissionsTableMigration } from './migrations/002-create-permissions-table';
import { CreateRolePermissionsTableMigration } from './migrations/003-create-role-permissions-table';
import { CreatePrincipalRolesTableMigration } from './migrations/004-create-principal-roles-table';
/* eslint-enable max-len */

export class AuthzRbacMigrations extends MigrationPackage {
	override name = '@riao/authz-rbac';
	override package = '@riao/authz-rbac';

	public async getMigrations(): Promise<
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		Record<string, typeof Migration<any>>
		> {
		return {
			'create-roles-table': CreateRolesTableMigration,
			'create-permissions-table': CreatePermissionsTableMigration,
			'create-role-permissions-table':
				CreateRolePermissionsTableMigration,
			'create-principal-roles-table': CreatePrincipalRolesTableMigration,
		};
	}
}
