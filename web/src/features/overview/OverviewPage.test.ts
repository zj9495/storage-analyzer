import { describe, expect, it } from 'vitest'
import { volumeSamplesQuery } from './OverviewPage'

describe('容量采样查询契约', () => {
  it('把范围映射为 from/to 并传递所选 resolution', () => {
    expect(volumeSamplesQuery('2026-09-01T00:00:00Z', '2026-09-08T00:00:00Z', 'raw')).toEqual({
      from: '2026-09-01T00:00:00Z',
      to: '2026-09-08T00:00:00Z',
      resolution: 'raw',
      page_size: 100,
    })
  })

  it('未选择范围时不增加未定义的查询值', () => {
    expect(volumeSamplesQuery(undefined, undefined, 'day')).toEqual({
      from: undefined,
      to: undefined,
      resolution: 'day',
      page_size: 100,
    })
  })
})
