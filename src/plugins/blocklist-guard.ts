import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { ForbiddenError } from '../lib/errors.js';
import type { BlocklistService } from '../modules/blocklist/blocklist.service.js';

export interface BlocklistGuardOptions {
  blocklistService: BlocklistService;
}

/**
 * Enforces the blocklist on every request.
 *
 * Runs as an `onRequest` hook: the earliest point in the Fastify lifecycle, before body
 * parsing, validation, auth and rate limiting. A blocked client gets 403 without the server
 * spending work on its payload.
 *
 * request.ip is the socket address unless TRUST_PROXY is enabled, in which case it is taken
 * from X-Forwarded-For. Only enable TRUST_PROXY behind a proxy you control, otherwise
 * clients can spoof that header and bypass the blocklist.
 */
export const blocklistGuardPlugin = fp((app: FastifyInstance, opts: BlocklistGuardOptions) => {
  app.addHook('onRequest', async (request) => {
    const match = opts.blocklistService.findMatch(request.ip);
    if (!match) return;

    await opts.blocklistService.recordHit(match);
    request.log.warn({ ip: request.ip, rule: match.cidr }, 'blocked request from blocklisted IP');
    throw new ForbiddenError('Your IP address is blocked', 'IP_BLOCKED');
  });
});
