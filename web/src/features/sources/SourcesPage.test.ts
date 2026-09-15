import { describe, expect, it } from 'vitest'
import { sourceUpdatePayload, volumeUpdatePayload } from './SourcesPage'

describe('卷 PATCH 请求体', () => {
  it('只提交卷 API 定义的可修改字段', () => {
    expect(volumeUpdatePayload({ name: 'media-volume', capacity_source_id: 'source-1' })).toEqual({
      name: 'media-volume',
      capacity_source_id: 'source-1',
    })
  })
})

describe('数据源 PATCH 请求体', () => {
  it('只提交 Axum PATCH 实际接受的 SourceUpdate 字段', () => {
    const payload = sourceUpdatePayload({
      name: 'media',
      mount_key: 'approved',
      relative_root: 'share',
      volume_id: null,
      storage_kind: 'local',
      read_policy: 'metadata_only',
      write_enabled: false,
      protected: true,
      exclusions: ['**/*.tmp'],
    })

    expect(payload).toEqual({
      name: 'media',
      read_policy: 'metadata_only',
      write_enabled: false,
      exclusions: ['**/*.tmp'],
    })
    expect(payload).not.toHaveProperty('mount_key')
    expect(payload).not.toHaveProperty('relative_root')
    expect(payload).not.toHaveProperty('volume_id')
    expect(payload).not.toHaveProperty('storage_kind')
    expect(payload).not.toHaveProperty('protected')
  })

  it('允许用空数组清除已有排除规则', () => {
    expect(sourceUpdatePayload({
      name: 'media',
      mount_key: 'approved',
      relative_root: 'share',
      volume_id: null,
      storage_kind: 'local',
      read_policy: 'metadata_only',
      write_enabled: false,
      protected: true,
      exclusions: [],
    }).exclusions).toEqual([])
  })
})
