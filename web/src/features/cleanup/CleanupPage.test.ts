import { describe, expect, it } from 'vitest'
import { cleanupActionQuery, cleanupPlanPayload, cleanupQuarantineQuery, type CleanupForm } from './CleanupPage'

describe('清理计划请求体', () => {
  it('使用多个真实重复组和 entry_id 选择值构建请求', () => {
    const values: CleanupForm = {
      report_id: 'report-1',
      groups: [
        { group_id: '7', keep_entry_ids: ['101'], target_entry_ids: ['102', '103'] },
        { group_id: '8', keep_entry_ids: ['201'], target_entry_ids: ['202'] },
      ],
    }

    expect(cleanupPlanPayload(values)).toEqual({
      report_id: 'report-1',
      groups: [
        { group_id: '7', keep_entry_ids: ['101'], target_entry_ids: ['102', '103'] },
        { group_id: '8', keep_entry_ids: ['201'], target_entry_ids: ['202'] },
      ],
    })
  })
})

describe('清理分页请求参数', () => {
  it('隔离区首请求不带游标，后续请求使用服务端游标', () => {
    expect(cleanupQuarantineQuery(null)).toEqual({ cursor: undefined, page_size: 50 })
    expect(cleanupQuarantineQuery('opaque-quarantine-cursor')).toEqual({ cursor: 'opaque-quarantine-cursor', page_size: 50 })
  })

  it('清理动作明细使用服务端游标', () => {
    expect(cleanupActionQuery(null)).toEqual({ cursor: undefined, page_size: 50 })
    expect(cleanupActionQuery('opaque-action-cursor')).toEqual({ cursor: 'opaque-action-cursor', page_size: 50 })
  })
})
