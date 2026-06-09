import { MigrationInterface, QueryRunner, Table } from "typeorm";

/**
 * Adds the `login_passwords` table used by the built-in "password" login
 * system (app/server/lib/PasswordLogin.ts). Each row stores a scrypt password
 * hash for a user, keyed by the user's id. The table is only populated when the
 * password login system is enabled (GRIST_PASSWORD_LOGIN=true).
 */
export class LoginPasswords1780500000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: "login_passwords",
        columns: [
          {
            name: "user_id",
            type: "integer",
            isPrimary: true,
          },
          {
            name: "password_hash",
            type: "varchar",
          },
        ],
        foreignKeys: [
          {
            columnNames: ["user_id"],
            referencedColumnNames: ["id"],
            referencedTableName: "users",
            // Drop the password when the user is deleted.
            onDelete: "CASCADE",
          },
        ],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable("login_passwords");
  }
}
