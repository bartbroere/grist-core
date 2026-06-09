import { User } from "app/gen-server/entity/User";

import {
  BaseEntity,
  Column,
  Entity,
  JoinColumn,
  OneToOne,
  PrimaryColumn,
} from "typeorm";

/**
 * A password credential for the built-in "password" login system (see
 * app/server/lib/PasswordLogin.ts). One row per user that has registered with
 * an email and password. The hash is produced by scrypt and stored in a
 * self-describing string format, so no external service is involved.
 *
 * This table only exists to support the optional self-hosted password login.
 * Installations using OIDC, SAML, forward-auth, etc. never write to it.
 */
@Entity({ name: "login_passwords" })
export class LoginPassword extends BaseEntity {
  // Shares its primary key with the users table: one password per user.
  @PrimaryColumn({ name: "user_id", type: Number })
  public userId: number;

  @OneToOne(type => User)
  @JoinColumn({ name: "user_id" })
  public user: User;

  // Encoded password hash, in the form "scrypt$<saltHex>$<hashHex>".
  @Column({ name: "password_hash", type: String })
  public passwordHash: string;
}
