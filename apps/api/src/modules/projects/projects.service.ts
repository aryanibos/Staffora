import type { AuthenticatedUser } from '../../common/auth/types.js'
import { projectsRepository } from './projects.repository.js'
import { projectsPolicy } from './projects.policy.js'
import { NotFoundError } from '../../common/errors/app-error.js'

export const projectsService = {
  async getProjects(_params: Record<string, unknown>, _user: AuthenticatedUser) {
    // TODO: Implement projects query and role filtering in Sprint 1 (PIC: Saiful & Jundy)
    return {
      data: [],
      total: 0,
      page: 1,
      pageSize: 10,
    }
  },

  async createProject(_data: Record<string, unknown>, _user: AuthenticatedUser) {
    // TODO: Implement project creation logic and validations in Sprint 1 (PIC: Saiful & Jundy)
    return null
  },

  async getProjectDetail(id: string, _user: AuthenticatedUser) {
    const project = await projectsRepository.findById(id)
    if (project) {
      return project
    }
    return {
      id,
      name: 'Project Foundation Scaffold',
      status: 'PLANNED',
      staffingRequirements: [],
      allocations: [],
    }
  },

  async updateProject(id: string, _data: Record<string, unknown>, user: AuthenticatedUser) {
    const project = await projectsRepository.findById(id)
    if (!project) {
      throw new NotFoundError('Project not found.')
    }

    projectsPolicy.assertCanUpdate(user, project.projectManagerEmployeeId)

    return {
      id: project.id,
      name: project.name,
      status: project.status,
      message: 'Project updated scaffold',
    }
  },
}
