import { describe, expect, it } from 'vitest'
import { currentReportQuerySpec, reportExportSection } from './ReportDetailPage'

describe('报告详情导出契约', () => {
  it('把当前文件筛选转换为后端 QuerySpec', () => {
    expect(currentReportQuerySpec({
      activeTab: 'files',
      metric: 'logical_bytes',
      parentEntryId: '42',
      nameContains: 'backup',
      ownerUid: '1001',
      rankingKind: 'largest',
    })).toEqual({
      include_descendants: true,
      name_contains: 'backup',
      owner_uids: [1001],
      metric: 'logical_bytes',
      sort: 'size_desc',
    })
  })

  it('按当前栏目选择真实导出 section', () => {
    expect(reportExportSection('folders', 'largest')).toBe('folders')
    expect(reportExportSection('rankings', 'recent')).toBe('recently_modified')
    expect(reportExportSection('summary', 'largest')).toBe('full_report')
  })
})
