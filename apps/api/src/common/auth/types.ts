/* eslint-disable @typescript-eslint/no-namespace */
export const ROLES = {
  ADMIN: 'ADMIN',
  PROJECT_MANAGER: 'PROJECT_MANAGER',
  RESOURCE_MANAGER: 'RESOURCE_MANAGER',
  EMPLOYEE: 'EMPLOYEE',
} as const

export type Role = (typeof ROLES)[keyof typeof ROLES]

export const ROLE_VALUES: readonly Role[] = Object.values(ROLES)


export interface AuthenticatedUser {
  id: string
  email: string
  role: Role
  isActive: boolean
  employeeId?: string | null
  employee?: {
    id: string
    employeeCode: string
    fullName: string
    workEmail: string
    departmentId: string
    departmentName: string
    jobRoleId: string
    jobRoleTitle: string
  } | null
}

declare module 'express-session' {
  interface SessionData {
    userId?: string
    csrfToken?: string
  }
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser
    }
  }
}
