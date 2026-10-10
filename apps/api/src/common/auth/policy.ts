import { UnauthorizedError, ForbiddenError, NotFoundError } from '../errors/app-error.js'
import { ROLES, type Role, type AuthenticatedUser } from './types.js'

export interface LinkageValidationResult {
  valid: boolean
  reason?: string
}

/**
 * Asserts that the request identity exists and is active.
 * Throws 401 UnauthorizedError if missing or inactive.
 */
export function assertAuth(
  user: AuthenticatedUser | undefined,
  message = 'Authentication required to access this resource.',
): asserts user is AuthenticatedUser {
  if (!user) {
    throw new UnauthorizedError(message)
  }
  if (!user.isActive) {
    throw new UnauthorizedError('User account is inactive.')
  }
}

/**
 * Asserts that the authenticated user possesses one of the allowed roles.
 * Throws 403 ForbiddenError if role is not permitted.
 */
export function assertRole(
  user: AuthenticatedUser,
  allowedRoles: readonly Role[],
  message = 'You do not have permission to perform this action.',
): void {
  if (!allowedRoles.includes(user.role)) {
    throw new ForbiddenError(message)
  }
}

/**
 * General policy assertion.
 * Throws 403 ForbiddenError if the boolean condition is false.
 */
export function assertPolicy(
  allowed: boolean,
  message = 'You do not have permission to perform this action.',
): void {
  if (!allowed) {
    throw new ForbiddenError(message)
  }
}

/**
 * Non-disclosure policy assertion.
 * When an unauthorized caller or non-existent resource is checked,
 * hides existence by returning 404 NotFoundError rather than 403 ForbiddenError.
 */
export function assertPolicyOrNotFound(
  allowed: boolean,
  resourceFound = true,
  notFoundMessage = 'Resource not found.',
): void {
  if (!resourceFound || !allowed) {
    throw new NotFoundError(notFoundMessage)
  }
}

/**
 * Validates whether user-to-employee linkage conforms to application rules.
 * Employees and Project Managers require linkage to an employee profile.
 */
export function validateUserEmployeeLinkage(user: {
  role: Role
  employeeId?: string | null
}): LinkageValidationResult {
  if (user.role === ROLES.EMPLOYEE || user.role === ROLES.PROJECT_MANAGER) {
    if (!user.employeeId || user.employeeId.trim() === '') {
      return {
        valid: false,
        reason: `Role ${user.role} requires linkage to an active employee record.`,
      }
    }
  }
  return { valid: true }
}

/**
 * Asserts that the authenticated user has a linked employee ID.
 * Returns the non-null employee ID or throws 403 ForbiddenError.
 */
export function requireLinkedEmployee(user: AuthenticatedUser): string {
  if (!user.employeeId) {
    throw new ForbiddenError('User account is not linked to an employee profile.')
  }
  return user.employeeId
}

/**
 * Policy helper for viewing employee profile data.
 * - Admin, Resource Manager, and Project Manager can view all employee profiles.
 * - Employee role can ONLY view their own profile (user.employeeId === targetEmployeeId).
 */
export function canAccessEmployeeProfile(
  user: AuthenticatedUser,
  targetEmployeeId: string,
): boolean {
  if (
    user.role === ROLES.ADMIN ||
    user.role === ROLES.RESOURCE_MANAGER ||
    user.role === ROLES.PROJECT_MANAGER
  ) {
    return true
  }
  if (user.role === ROLES.EMPLOYEE) {
    return Boolean(user.employeeId && user.employeeId === targetEmployeeId)
  }
  return false
}

/**
 * Asserts that the user is authorized to access the given employee profile.
 */
export function assertCanAccessEmployeeProfile(
  user: AuthenticatedUser,
  targetEmployeeId: string,
  message = 'You do not have permission to access another employee profile.',
): void {
  if (!canAccessEmployeeProfile(user, targetEmployeeId)) {
    throw new ForbiddenError(message)
  }
}

/**
 * Checks if the user is the assigned Project Manager for the specified project.
 */
export function isProjectManagerOwner(
  user: AuthenticatedUser,
  projectManagerEmployeeId: string | null | undefined,
): boolean {
  if (user.role !== ROLES.PROJECT_MANAGER || !user.employeeId || !projectManagerEmployeeId) {
    return false
  }
  return user.employeeId === projectManagerEmployeeId
}

/**
 * Policy helper for managing (creating/updating) projects.
 * - Admin can manage any project.
 * - Project Manager can manage only their assigned projects.
 */
export function canManageProject(
  user: AuthenticatedUser,
  projectManagerEmployeeId: string | null | undefined,
): boolean {
  if (user.role === ROLES.ADMIN) return true
  return isProjectManagerOwner(user, projectManagerEmployeeId)
}

/**
 * Asserts that the user is authorized to manage the given project.
 */
export function assertCanManageProject(
  user: AuthenticatedUser,
  projectManagerEmployeeId: string | null | undefined,
  message = 'You do not have permission to manage this project.',
): void {
  if (!canManageProject(user, projectManagerEmployeeId)) {
    throw new ForbiddenError(message)
  }
}

/**
 * Policy helper for viewing projects.
 * - All authenticated roles can view project directory.
 */
export function canViewProject(
  _user: AuthenticatedUser,
  _projectManagerEmployeeId?: string | null,
): boolean {
  return true
}

/**
 * Policy helper for managing allocations.
 * - Admin and Resource Manager can manage allocations across any project.
 * - Project Manager can manage allocations only for their assigned projects.
 */
export function canManageAllocation(
  user: AuthenticatedUser,
  projectManagerEmployeeId: string | null | undefined,
): boolean {
  if (user.role === ROLES.ADMIN || user.role === ROLES.RESOURCE_MANAGER) return true
  return isProjectManagerOwner(user, projectManagerEmployeeId)
}

/**
 * Asserts that the user is authorized to manage allocations for the given project.
 */
export function assertCanManageAllocation(
  user: AuthenticatedUser,
  projectManagerEmployeeId: string | null | undefined,
  message = 'You do not have permission to manage allocations for this project.',
): void {
  if (!canManageAllocation(user, projectManagerEmployeeId)) {
    throw new ForbiddenError(message)
  }
}
