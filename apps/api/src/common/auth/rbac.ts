import type { RequestHandler } from 'express'
import { UnauthorizedError, ForbiddenError } from '../errors/app-error.js'
import type { Role } from './types.js'
export * from './policy.js'

/**
 * Middleware ensuring the client has an active authenticated session.
 * Throws 401 UnauthorizedError if no user or user is inactive.
 */
export function requireAuth(): RequestHandler {
  return (req, _res, next) => {
    if (!req.user || !req.user.isActive) {
      return next(new UnauthorizedError('Authentication required to access this resource.'))
    }
    next()
  }
}

/**
 * Middleware enforcing that the authenticated user possesses one of the allowed roles.
 * Throws 401 if unauthenticated, or 403 ForbiddenError if user's role is not permitted.
 */
export function requireRole(...allowedRoles: Role[]): RequestHandler {
  return (req, _res, next) => {
    if (!req.user || !req.user.isActive) {
      return next(new UnauthorizedError('Authentication required to access this resource.'))
    }
    if (!allowedRoles.includes(req.user.role)) {
      return next(new ForbiddenError('You do not have permission to perform this action.'))
    }
    next()
  }
}

/**
 * Middleware verifying that the authenticated user has a linked employee profile.
 * Throws 401 if unauthenticated, or 403 ForbiddenError if employeeId is missing.
 */
export function requireLinkedEmployee(): RequestHandler {
  return (req, _res, next) => {
    if (!req.user || !req.user.isActive) {
      return next(new UnauthorizedError('Authentication required to access this resource.'))
    }
    if (!req.user.employeeId) {
      return next(new ForbiddenError('User account is not linked to an employee profile.'))
    }
    next()
  }
}
