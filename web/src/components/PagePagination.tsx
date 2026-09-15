import { Button, Space, Typography } from 'antd'
import type { ListMeta } from '../api/types'

export function PagePagination({
  meta,
  loading,
  onNext,
}: {
  meta: ListMeta | undefined
  loading: boolean
  onNext: (cursor: string) => void
}) {
  if (!meta) return null
  return (
    <Space style={{ marginTop: 16 }}>
      <Typography.Text type="secondary">
        {meta.total_known === null ? '总数按需计算' : `共 ${meta.total_known} 条`}
        {meta.truncated ? ' · 结果已截断' : ''}
      </Typography.Text>
      {meta.next_cursor ? (
        <Button loading={loading} onClick={() => onNext(meta.next_cursor as string)}>
          加载下一页
        </Button>
      ) : (
        <Typography.Text type="secondary">已到末页</Typography.Text>
      )}
    </Space>
  )
}
