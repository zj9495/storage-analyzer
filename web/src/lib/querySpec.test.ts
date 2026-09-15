import { describe, expect, it } from 'vitest'
import { filterSignature, serializeQuerySpec } from './querySpec'

describe('serializeQuerySpec', () => {
  it('筛选键按字典序输出，结果可复现', () => {
    const a = serializeQuerySpec({
      filters: { size_min: 1024, category: 'video' },
    }).toString()
    const b = serializeQuerySpec({
      filters: { category: 'video', size_min: 1024 },
    }).toString()
    expect(a).toBe(b)
    expect(a).toBe('filter%5Bcategory%5D=video&filter%5Bsize_min%5D=1024')
  })

  it('数组值排序后重复出现', () => {
    const params = serializeQuerySpec({
      filters: { owner: ['bob', 'alice'] },
    })
    expect(params.getAll('filter[owner]')).toEqual(['alice', 'bob'])
  })

  it('空值与未设置值不写入 URL', () => {
    const params = serializeQuerySpec({
      filters: { a: undefined, b: null, c: '', d: 'x' },
    })
    expect(params.toString()).toBe('filter%5Bd%5D=x')
  })

  it('排序编码为 sort=key,-key2', () => {
    const params = serializeQuerySpec({
      sort: [
        { key: 'size', order: 'desc' },
        { key: 'name', order: 'asc' },
      ],
    })
    expect(params.get('sort')).toBe('-size,name')
  })

  it('游标写入 cursor 参数', () => {
    const params = serializeQuerySpec({ cursor: 'abc123' })
    expect(params.get('cursor')).toBe('abc123')
  })
})

describe('filterSignature', () => {
  it('签名与游标无关（用于筛选变化时重置游标）', () => {
    const base = { filters: { category: 'video' } }
    expect(filterSignature({ ...base, cursor: 'c1' })).toBe(
      filterSignature({ ...base, cursor: 'c2' }),
    )
    expect(filterSignature({ ...base, cursor: null })).toBe(
      filterSignature(base),
    )
  })

  it('筛选变化时签名变化', () => {
    expect(filterSignature({ filters: { category: 'video' } })).not.toBe(
      filterSignature({ filters: { category: 'image' } }),
    )
  })
})
