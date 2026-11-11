import type { Database } from '../../db/database.js';

export type Role = 'admin' | 'analyst';

export interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: Role;
  createdAt: string;
}

/**
 * Repository contract. Methods are async so an implementation backed by a network
 * database (e.g. PostgreSQL) can replace the SQLite one without changing services.
 */
export interface UserRepository {
  findById(id: string): Promise<User | undefined>;
  findByUsername(username: string): Promise<User | undefined>;
  create(user: User): Promise<void>;
  count(): Promise<number>;
}

interface UserRow {
  id: string;
  username: string;
  password_hash: string;
  role: Role;
  created_at: string;
}

const toUser = (row: UserRow): User => ({
  id: row.id,
  username: row.username,
  passwordHash: row.password_hash,
  role: row.role,
  createdAt: row.created_at,
});

export class SqliteUserRepository implements UserRepository {
  constructor(private readonly db: Database) {}

  findById(id: string): Promise<User | undefined> {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
    return Promise.resolve(row ? toUser(row) : undefined);
  }

  findByUsername(username: string): Promise<User | undefined> {
    const row = this.db.prepare('SELECT * FROM users WHERE username = ?').get(username) as
      UserRow | undefined;
    return Promise.resolve(row ? toUser(row) : undefined);
  }

  create(user: User): Promise<void> {
    this.db
      .prepare(
        'INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
      )
      .run(user.id, user.username, user.passwordHash, user.role, user.createdAt);
    return Promise.resolve();
  }

  count(): Promise<number> {
    const row = this.db.prepare('SELECT COUNT(*) AS total FROM users').get() as { total: number };
    return Promise.resolve(row.total);
  }
}
