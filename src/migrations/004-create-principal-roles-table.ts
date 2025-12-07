import { CreateTimestampColumn, UUIDKeyColumn } from '@riao/dbal/column-pack';
import { ColumnType, Migration } from '@riao/dbal';

export class CreatePrincipalRolesTableMigration extends Migration {
	override async up(): Promise<void> {
		await this.ddl.createTable({
			name: 'iam_rbac_principal_roles',
			columns: [
				UUIDKeyColumn,
				{
					name: 'principal_id',
					type: ColumnType.UUID,
					required: true,
					fk: {
						referencesTable: 'iam_principals',
						referencesColumn: 'id',
						onDelete: 'CASCADE',
					},
				},
				{
					name: 'role_id',
					type: ColumnType.UUID,
					required: true,
					fk: {
						referencesTable: 'iam_rbac_roles',
						referencesColumn: 'id',
						onDelete: 'CASCADE',
					},
				},
				CreateTimestampColumn,
				{
					name: 'deactivate_timestamp',
					type: ColumnType.TIMESTAMP,
				},
			],
		});

		// TODO: Prevent duplicate principal_id + role_id entries?
	}

	override async down(): Promise<void> {
		await this.ddl.dropTable({
			tables: ['iam_rbac_principal_roles'],
		});
	}
}
