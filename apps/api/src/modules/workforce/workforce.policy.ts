import type { AuthenticatedUser } from '../../common/auth/types.js'
import {
  canAccessEmployeeProfile,
  assertCanAccessEmployeeProfile,
} from '../../common/auth/policy.js'

export const workforcePolicy = {
  canViewEmployee(user: AuthenticatedUser, employeeId: string): boolean {
    return canAccessEmployeeProfile(user, employeeId)
  },

  canManageEmployee(user: AuthenticatedUser): boolean {
    return user.role === 'ADMIN' || user.role === 'RESOURCE_MANAGER'
  },

  assertCanViewEmployee(
    user: AuthenticatedUser,
    employeeId: string,
    message = 'You do not have permission to access another employee profile.',
  ): void {
    assertCanAccessEmployeeProfile(user, employeeId, message)
  },
}
