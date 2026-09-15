import { Alert, Button, Card, Empty, Select, Space, Table, Typography } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../../api/client'
import type { ApiEnvelope, ComparisonResult, ListMeta } from '../../api/types'
import { PagePagination } from '../../components/PagePagination'
import { QueryState } from '../../components/QueryState'

type ComparisonResponse = ApiEnvelope<ComparisonResult> & { meta: ListMeta }
type ComparisonSection = 'folders' | 'owners' | 'categories' | 'files'

function displayValue(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (value === null) return 'null'
  return JSON.stringify(value)
}

function comparisonColumns(rows: Record<string, unknown>[]) {
  const keys = Array.from(new Set(rows.flatMap((row) => Object.keys(row))))
  return keys.map((key) => ({
    title: key,
    dataIndex: key,
    render: (value: unknown) => displayValue(value),
  }))
}

export function ComparisonResultPanel({
  comparisonId,
  onClose,
}: {
  comparisonId: string
  onClose: () => void
}) {
  const [section, setSection] = useState<ComparisonSection>()
  const [cursor, setCursor] = useState<string>()
  const comparison = useQuery<ComparisonResponse>({
    queryKey: ['comparisons', comparisonId, { section, cursor }],
    queryFn: async ({ signal }) =>
      (await api.get<ComparisonResult>(`/api/v1/comparisons/${encodeURIComponent(comparisonId)}`, {
        signal,
        query: { section, cursor, page_size: 50 },
      })) as ComparisonResponse,
    refetchInterval: (query) =>
      query.state.data?.data.state === 'pending' ? 2_000 : false,
  })

  return (
    <Card
      title={`比较结果：${comparisonId}`}
      extra={<Button onClick={onClose}>关闭</Button>}
      style={{ marginTop: 16 }}
    >
      <Space wrap style={{ marginBottom: 16 }}>
        <Select
          allowClear
          placeholder="按栏目查看"
          value={section}
          options={[
            { value: 'folders', label: '目录' },
            { value: 'owners', label: '用户' },
            { value: 'categories', label: '分类' },
            { value: 'files', label: '文件' },
          ]}
          onChange={(value: ComparisonSection | undefined) => {
            setSection(value)
            setCursor(undefined)
          }}
        />
      </Space>
      <QueryState query={comparison}>
        {(response) => {
          const result = response.data
          if (result.state === 'pending') {
            return (
              <Alert
                type="info"
                showIcon
                message="比较正在计算"
                description="结果尚未完成，当前空列表不代表没有差异。页面会自动刷新。"
              />
            )
          }
          if (result.state === 'failed') {
            return (
              <Alert
                type="error"
                showIcon
                message="比较失败"
                description={result.error === null || result.error === undefined ? '服务端未提供错误详情' : displayValue(result.error)}
              />
            )
          }
          const rows = result.rows as Record<string, unknown>[]
          return (
            <>
              <Alert
                type={result.comparable ? 'success' : 'warning'}
                showIcon
                message={result.comparable ? '两份报告可比' : '两份报告不完全可比'}
                description="差异只表示两份报告在各自观测时点的结果变化，不代表文件一定被删除。"
                style={{ marginBottom: 16 }}
              />
              <Typography.Paragraph>
                摘要：<Typography.Text code>{JSON.stringify(result.summary)}</Typography.Text>
              </Typography.Paragraph>
              {rows.length === 0 ? (
                <Empty description="所选比较栏目没有差异行" />
              ) : (
                <Table<Record<string, unknown>>
                  rowKey="row_key"
                  dataSource={rows}
                  pagination={false}
                  scroll={{ x: true }}
                  columns={comparisonColumns(rows)}
                />
              )}
              <PagePagination
                meta={response.meta}
                loading={comparison.isFetching}
                onNext={setCursor}
              />
            </>
          )
        }}
      </QueryState>
    </Card>
  )
}
