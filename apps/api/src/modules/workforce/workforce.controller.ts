import type { Request, Response, NextFunction } from 'express'
import { sendSuccess, sendList } from '../../common/http/response.js'
import { workforceService } from './workforce.service.js'
import { workforcePolicy } from './workforce.policy.js'

export const workforceController = {
  async getDepartments(_req: Request, res: Response, next: NextFunction) {
    try {
      const items = await workforceService.getDepartments()
      return sendSuccess(res, items)
    } catch (err) {
      next(err)
    }
  },

  async createDepartment(req: Request, res: Response, next: NextFunction) {
    try {
      const item = await workforceService.createDepartment(req.body)
      return res.status(201).json({ data: item })
    } catch (err) {
      next(err)
    }
  },

  async getJobRoles(req: Request, res: Response, next: NextFunction) {
    try {
      const items = await workforceService.getJobRoles(req.query.departmentId as string | undefined)
      return sendSuccess(res, items)
    } catch (err) {
      next(err)
    }
  },

  async createJobRole(req: Request, res: Response, next: NextFunction) {
    try {
      const item = await workforceService.createJobRole(req.body)
      return res.status(201).json({ data: item })
    } catch (err) {
      next(err)
    }
  },

  async getEmployees(req: Request, res: Response, next: NextFunction) {
    try {
      const result = await workforceService.getEmployees(req.query)
      return sendList(res, result.data, {
        page: result.page,
        pageSize: result.pageSize,
        total: result.total,
      })
    } catch (err) {
      next(err)
    }
  },

  async createEmployee(req: Request, res: Response, next: NextFunction) {
    try {
      const item = await workforceService.createEmployee(req.body)
      return res.status(201).json({ data: item })
    } catch (err) {
      next(err)
    }
  },

  async getEmployeeDetail(req: Request, res: Response, next: NextFunction) {
    try {
      if (req.user) {
        workforcePolicy.assertCanViewEmployee(req.user, req.params.id as string)
      }
      const item = await workforceService.getEmployeeDetail(req.params.id as string)
      return sendSuccess(res, item)
    } catch (err) {
      next(err)
    }
  },

  async updateEmployee(req: Request, res: Response, next: NextFunction) {
    try {
      const item = await workforceService.updateEmployee(req.params.id as string, req.body)
      return sendSuccess(res, item)
    } catch (err) {
      next(err)
    }
  },
}
