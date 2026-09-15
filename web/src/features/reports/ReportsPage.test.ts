import { describe, expect, it } from 'vitest'
import type { ReportStatus } from '../../api/types'
import { reportStatusLabels } from './ReportsPage'

describe('报告状态契约', () => {
  it('只暴露后端报告状态', () => {
    const statuses: ReportStatus[] = ['succeeded', 'partial', 'failed']

    expect(Object.keys(reportStatusLabels).sort()).toEqual(['failed', 'partial', 'succeeded'])
    expect(statuses.map((status) => reportStatusLabels[status])).toEqual(['成功', '部分成功', '失败'])
    expect(reportStatusLabels).not.toHaveProperty('complete')
    expect(reportStatusLabels).not.toHaveProperty('cancelled')
  })
})
