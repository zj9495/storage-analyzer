import { afterEach, describe, expect, it, vi } from 'vitest'
import { listAllSources, profilePayload, type ProfileForm } from './ProfilesPage'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('ProfileConfig 编辑请求体', () => {
  it('保留 scope、重复检测、通知和资源配置字段', () => {
    const values: ProfileForm = {
      name: 'weekly',
      description: 'full config',
      enabled: true,
      scope_mode: 'selected',
      source_ids: ['source-1'],
      include_future_registered: true,
      include_globs: ['**/*.iso'],
      exclude_globs: ['**/*.tmp'],
      file_kind_policy: 'all_metadata',
      sections: ['volume', 'duplicates'],
      owner_ids_to_list: ['1001'],
      rank_limit: 50,
      duplicates_enabled: true,
      duplicates_match_name: true,
      duplicates_match_mtime: true,
      duplicates_min_size_bytes: '10',
      duplicates_max_size_bytes: '1000',
      duplicates_max_listed_files: 20,
      duplicates_hash_budget_bytes: '2048',
      duplicates_content_read_policy: 'allow_remote_recall',
      schedule_type: 'cron',
      schedule_expression: '0 2 * * 0',
      schedule_days_of_week: [],
      schedule_timezone: 'UTC',
      misfire_policy: 'run_once',
      overlap_policy: 'skip',
      report_keep_count: 12,
      detail_keep_count: 4,
      notification_recipients: ['ops@example.test'],
      notification_notify_on: ['partial'],
      notification_attach_summary: true,
      notification_public_base_url: 'https://nas.example.test',
      metadata_workers: 2,
      hash_workers: 1,
      read_limit_mib_s: 10,
      io_priority: 'low',
    }

    expect(profilePayload(values)).toEqual({
      name: 'weekly',
      description: 'full config',
      enabled: true,
      scope: { mode: 'selected', source_ids: ['source-1'], include_future_registered: true, include_globs: ['**/*.iso'], exclude_globs: ['**/*.tmp'], file_kind_policy: 'all_metadata' },
      sections: ['volume', 'duplicates'],
      owner_ids_to_list: [1001],
      duplicates: { enabled: true, match_name: true, match_mtime: true, min_size_bytes: '10', max_size_bytes: '1000', max_listed_files: 20, hash_budget_bytes: '2048', content_read_policy: 'allow_remote_recall' },
      rank_limit: 50,
      schedule: { type: 'cron', expression: '0 2 * * 0', time_of_day: undefined, days_of_week: [], day_of_month: undefined, timezone: 'UTC', misfire_policy: 'run_once', overlap_policy: 'skip' },
      retention: { report_keep_count: 12, detail_keep_count: 4 },
      notifications: { recipients: ['ops@example.test'], notify_on: ['partial'], attach_summary: true, public_base_url: 'https://nas.example.test' },
      resources: { metadata_workers: 2, hash_workers: 1, read_limit_mib_s: 10, io_priority: 'low' },
    })
  })
})

describe('Profile 数据源选择器', () => {
  it('按分页游标读取全部已登记数据源', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        data: [{ id: 'source-1', name: 'Source 1' }],
        meta: { next_cursor: 'cursor-2', page_size: 200, total_known: 2, truncated: true, detail_available: true },
        request_id: 'request-1',
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        data: [{ id: 'source-2', name: 'Source 2' }],
        meta: { next_cursor: null, page_size: 200, total_known: 2, truncated: false, detail_available: true },
        request_id: 'request-2',
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(listAllSources(new AbortController().signal)).resolves.toEqual([
      { id: 'source-1', name: 'Source 1' },
      { id: 'source-2', name: 'Source 2' },
    ])
    expect(fetchMock).toHaveBeenCalledTimes(2)
    const secondUrl = new URL(fetchMock.mock.calls[1][0] as string, window.location.origin)
    expect(secondUrl.searchParams.get('cursor')).toBe('cursor-2')
    expect(secondUrl.searchParams.get('page_size')).toBe('200')
  })
})
