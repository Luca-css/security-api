import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { hasZodFastifySchemaValidationErrors } from 'fastify-type-provider-zod';
import { STATUS_CODES } from 'node:http';
import { AppError } from '../lib/errors.js';

/**
 * Every error leaves the API with the same shape:
 *
 * { statusCode, error, code, message, details?, requestId }
 *
 * 5xx messages are never forwarded to clients (they are logged instead).
 */
export interface ErrorBody {
  statusCode: number;
  error: string;
  code: string;
  message: string;
  details?: unknown;
  requestId: string;
}

function send(
  reply: FastifyReply,
  request: FastifyRequest,
  statusCode: number,
  code: string,
  message: string,
  details?: unknown,
) {
  const body: ErrorBody = {
    statusCode,
    error: STATUS_CODES[statusCode] ?? 'Error',
    code,
    message,
    requestId: request.id,
  };
  if (details !== undefined) body.details = details;
  return reply.code(statusCode).send(body);
}

export const errorHandlerPlugin = fp((app: FastifyInstance) => {
  app.setErrorHandler((error: FastifyError | AppError, request, reply) => {
    if (error instanceof AppError) {
      return send(reply, request, error.statusCode, error.code, error.message, error.details);
    }

    if (hasZodFastifySchemaValidationErrors(error)) {
      const issues = error.validation.map((issue) => ({
        path: issue.instancePath.replace(/^\//, '').replaceAll('/', '.'),
        message: issue.message,
      }));
      return send(reply, request, 400, 'VALIDATION_ERROR', 'Request validation failed', {
        location: error.validationContext,
        issues,
      });
    }

    // Framework/plugin errors with a client status (malformed JSON, 413, 415, ...).
    const statusCode = error.statusCode ?? 500;
    if (statusCode >= 400 && statusCode < 500) {
      return send(reply, request, statusCode, error.code || 'BAD_REQUEST', error.message);
    }

    request.log.error({ err: error }, 'unhandled error');
    return send(reply, request, 500, 'INTERNAL_ERROR', 'Internal server error');
  });

  app.setNotFoundHandler((request, reply) =>
    send(reply, request, 404, 'NOT_FOUND', `Route ${request.method} ${request.url} not found`),
  );
});
