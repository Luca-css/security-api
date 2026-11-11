import { randomUUID } from 'node:crypto';
import { ConflictError, UnauthorizedError } from '../../lib/errors.js';
import { hashPassword, verifyPassword } from '../../lib/password.js';
import type { Role, User, UserRepository } from './user.repository.js';

export type PublicUser = Omit<User, 'passwordHash'>;

export function toPublicUser(user: User): PublicUser {
  return { id: user.id, username: user.username, role: user.role, createdAt: user.createdAt };
}

export class AuthService {
  /** Hash checked when the username does not exist, so both paths cost one scrypt call. */
  private dummyHash: Promise<string> | undefined;

  constructor(private readonly users: UserRepository) {}

  /**
   * Returns the user when credentials are valid. The same generic error is used for
   * "unknown user" and "wrong password" to avoid username enumeration.
   */
  async authenticate(username: string, password: string): Promise<PublicUser> {
    const user = await this.users.findByUsername(username);
    if (!user) {
      this.dummyHash ??= hashPassword(randomUUID());
      await verifyPassword(password, await this.dummyHash);
      throw new UnauthorizedError('Invalid username or password', 'INVALID_CREDENTIALS');
    }
    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      throw new UnauthorizedError('Invalid username or password', 'INVALID_CREDENTIALS');
    }
    return toPublicUser(user);
  }

  async createUser(input: { username: string; password: string; role: Role }): Promise<PublicUser> {
    const existing = await this.users.findByUsername(input.username);
    if (existing) {
      throw new ConflictError(`User '${input.username}' already exists`);
    }
    const user: User = {
      id: randomUUID(),
      username: input.username,
      passwordHash: await hashPassword(input.password),
      role: input.role,
      createdAt: new Date().toISOString(),
    };
    await this.users.create(user);
    return toPublicUser(user);
  }

  async getById(id: string): Promise<PublicUser | undefined> {
    const user = await this.users.findById(id);
    return user ? toPublicUser(user) : undefined;
  }

  /** Creates the initial admin from env vars when the users table is empty. */
  async ensureAdminUser(username: string, password: string): Promise<boolean> {
    if ((await this.users.count()) > 0) return false;
    await this.createUser({ username, password, role: 'admin' });
    return true;
  }
}
