import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Descriptions, Table, Tag } from 'antd'
import { api } from '../../api/client'
import type { AuditEvent, DiagnosticInfo } from '../../api/types'
import { PageHeader } from '../../components/PageHeader'
import { PagePagination } from '../../components/PagePagination'
import { QueryState } from '../../components/QueryState'
import { formatBytes } from '../../lib/format'

export function DiagnosticsPage() {
  const [auditCursor, setAuditCursor] = useState<string>()
  const diagnostics = useQuery({
    queryKey: ['diagnostics', 'info'],
    queryFn: async ({ signal }) =>
      (await api.get<DiagnosticInfo>('/api/v1/diagnostics', { signal })).data,
  })
  const audit = useQuery({
    queryKey: ['diagnostics', 'audit', auditCursor],
    queryFn: ({ signal }) => api.getPage<AuditEvent>('/api/v1/audit', { signal, query: { cursor: auditCursor, page_size: 50 } }),
  })

  return (
    <div>
      <PageHeader title="诊断与审计" description="能力矩阵、版本、资源与失败记录" />
      <QueryState query={diagnostics}>
        {(data) => (
          <Card title="诊断信息" style={{ marginBottom: 16 }}>
            <Descriptions bordered column={2}>
              <Descriptions.Item label="应用版本">{data.app_version}</Descriptions.Item>
              <Descriptions.Item label="SQLite 版本">{data.sqlite_version}</Descriptions.Item>
              <Descriptions.Item label="构建配置">{data.build?.profile}</Descriptions.Item>
              <Descriptions.Item label="目标架构">{data.build?.target}</Descriptions.Item>
              <Descriptions.Item label="系统架构">{data.runtime?.arch}</Descriptions.Item>
              <Descriptions.Item label="操作系统">{data.runtime?.os}</Descriptions.Item>
              <Descriptions.Item label="运行 UID">{data.runtime?.uid}</Descriptions.Item>
              <Descriptions.Item label="运行 GID">{data.runtime?.gid}</Descriptions.Item>
              <Descriptions.Item label="只读边界">
                <Tag>{data.runtime?.read_only_boundary ? '是' : '否'}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="进程 RSS">
                {data.runtime?.memory_rss_bytes !== undefined
                  ? formatBytes(data.runtime.memory_rss_bytes)
                  : undefined}
              </Descriptions.Item>
              <Descriptions.Item label="数据目录已用">
                {data.data_dir?.used_bytes !== undefined
                  ? formatBytes(data.data_dir.used_bytes)
                  : undefined}
              </Descriptions.Item>
              <Descriptions.Item label="数据目录剩余">
                {data.data_dir?.free_bytes !== undefined
                  ? formatBytes(data.data_dir.free_bytes)
                  : undefined}
              </Descriptions.Item>
              <Descriptions.Item label="扫描运行中">{data.scan_queue?.running}</Descriptions.Item>
              <Descriptions.Item label="扫描排队中">{data.scan_queue?.queued}</Descriptions.Item>
            </Descriptions>
            <Table
              style={{ marginTop: 16 }}
              rowKey="source_id"
              dataSource={data.sources}
              pagination={false}
              columns={[
                { title: '数据源 ID', dataIndex: 'source_id' },
                { title: '名称', dataIndex: 'name' },
                { title: '可用性', dataIndex: 'availability' },
              ]}
            />
          </Card>
        )}
      </QueryState>
      <QueryState query={audit}>
        {(page) => (
          <Card title="审计记录">
            <Table<AuditEvent>
              rowKey="id"
              dataSource={page.data}
              pagination={false}
              locale={{ emptyText: '暂无审计记录' }}
              columns={[
                { title: '时间', dataIndex: 'created_at' },
                { title: '操作者', render: (_, event) => event.actor.username },
                { title: '动作', dataIndex: 'action' },
                { title: '资源', render: (_, event) => `${event.resource.kind}:${event.resource.id}` },
                {
                  title: '结果',
                  dataIndex: 'result',
                  render: (result: AuditEvent['result']) => <Tag>{result}</Tag>,
                },
                { title: '请求 ID', dataIndex: 'request_id' },
              ]}
            />
            <PagePagination meta={page.meta} loading={audit.isFetching} onNext={setAuditCursor} />
          </Card>
        )}
      </QueryState>
    </div>
  )
}
