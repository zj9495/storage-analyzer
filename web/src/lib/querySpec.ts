/**
 * 可复现 QuerySpec（spec 15.8）：筛选、排序、报告 ID 写入路由 query 参数；
 * 翻页游标与筛选签名绑定，切换筛选时必须重置游标。
 */

export interface SortSpec {
  key: string
  order: 'asc' | 'desc'
}

export type FilterValue =
  | string
  | number
  | boolean
  | ReadonlyArray<string>
  | null
  | undefined

export interface QuerySpec {
  filters?: Record<string, FilterValue>
  sort?: ReadonlyArray<SortSpec>
  cursor?: string | null
}

/**
 * 将 QuerySpec 序列化为确定性的 URL 查询参数：
 * - 筛选键按字典序排序，数组值内部排序后重复出现（filter[key]=v1&filter[key]=v2）
 * - undefined / null / 空字符串视为未设置，不写入 URL
 * - 排序编码为 sort=key1,-key2（- 前缀表示降序）
 */
export function serializeQuerySpec(spec: QuerySpec): URLSearchParams {
  const params = new URLSearchParams()
  const filters = spec.filters ?? {}
  for (const key of Object.keys(filters).sort()) {
    const value = filters[key]
    if (value === undefined || value === null || value === '') continue
    if (Array.isArray(value)) {
      for (const item of [...value].sort()) {
        if (item !== '') params.append(`filter[${key}]`, item)
      }
    } else {
      params.set(`filter[${key}]`, String(value))
    }
  }
  if (spec.sort && spec.sort.length > 0) {
    params.set(
      'sort',
      spec.sort.map((s) => `${s.order === 'desc' ? '-' : ''}${s.key}`).join(','),
    )
  }
  if (spec.cursor) params.set('cursor', spec.cursor)
  return params
}

/**
 * 筛选签名：与 cursor 无关。用于判断“筛选是否变化”，变化时重置游标与选择项。
 */
export function filterSignature(spec: QuerySpec): string {
  const { cursor: _cursor, ...rest } = spec
  return serializeQuerySpec(rest).toString()
}
