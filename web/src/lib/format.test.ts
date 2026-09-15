import { describe, expect, it } from 'vitest'
import { formatBytes, formatDecimal, parseBytesDecimal } from './format'

describe('parseBytesDecimal', () => {
  it('解析整数字符串', () => {
    expect(parseBytesDecimal('1024')).toBe(1024n)
    expect(parseBytesDecimal(' -16 ')).toBe(-16n)
  })

  it('拒绝非整数字符串', () => {
    expect(() => parseBytesDecimal('12.5')).toThrow(TypeError)
    expect(() => parseBytesDecimal('abc')).toThrow(TypeError)
    expect(() => parseBytesDecimal('')).toThrow(TypeError)
    expect(() => parseBytesDecimal('1e6')).toThrow(TypeError)
  })
})

describe('formatBytes', () => {
  it('格式化基本单位', () => {
    expect(formatBytes('0')).toBe('0 B')
    expect(formatBytes('512')).toBe('512 B')
    expect(formatBytes('1024')).toBe('1.00 KiB')
    expect(formatBytes('1536')).toBe('1.50 KiB')
    expect(formatBytes('1048576')).toBe('1.00 MiB')
    expect(formatBytes('-1024')).toBe('-1.00 KiB')
  })

  it('支持 bigint 输入与自定义小数位', () => {
    expect(formatBytes(1073741824n)).toBe('1.00 GiB')
    expect(formatBytes('1536', 0)).toBe('1 KiB') // 0 位小数时只保留整数位（截断）
  })

  it('BigInt 安全：超过 2^53 的十进制字符串不丢精度', () => {
    // Number('9007199254740993') === 9007199254740992，精度已丢失
    expect(Number('9007199254740993')).toBe(Number('9007199254740992'))
    // BigInt 路径保留 1 字节之差（PiB 单位下第 18 位小数可见）
    expect(formatBytes('9007199254740992', 18)).toBe(
      '8.000000000000000000 PiB',
    )
    expect(formatBytes('9007199254740993', 18)).toBe(
      '8.000000000000000888 PiB',
    )
    expect(formatBytes('9007199254740993')).toBe('8.00 PiB')
  })
})

describe('formatDecimal', () => {
  it('千分位格式化且不经过 Number()', () => {
    expect(formatDecimal('12345678901234567890123')).toBe(
      '12,345,678,901,234,567,890,123',
    )
    expect(formatDecimal(-1234567n)).toBe('-1,234,567')
  })
})
