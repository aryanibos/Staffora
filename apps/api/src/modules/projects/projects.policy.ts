import type { AuthenticatedUser } from '../../common/auth/types.js'
import {
  canManageProject,
  canViewProject,
  assertCanManageProject,
  isProjectManagerOwner,
} from '../../common/auth/policy.js'

export const projectsPolicy = {
  canCreate(user: AuthenticatedUser): boolean {
    return user.role === 'ADMIN' || user.role === 'PROJECT_MANAGER'
  },

  canUpdate(user: AuthenticatedUser, projectManagerEmployeeId: string | null | undefined): boolean {
    return canManageProject(user, projectManagerEmployeeId)
  },

  canView(user: AuthenticatedUser, projectManagerEmployeeId?: string | null): boolean {
    return canViewProject(user, projectManagerEmployeeId)
  },

  isOwner(user: AuthenticatedUser, projectManagerEmployeeId: string | null | undefined): boolean {
    return isProjectManagerOwner(user, projectManagerEmployeeId)
  },

  assertCanUpdate(
    user: AuthenticatedUser,
    projectManagerEmployeeId: string | null | undefined,
    message = 'You do not have permission to manage this project.',
  ): void {
    assertCanManageProject(user, projectManagerEmployeeId, message)
  },
}
