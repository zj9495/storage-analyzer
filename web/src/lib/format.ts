const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'] as const

/**
 * 解析 DTO 中的字节数十进制字符串。只允许整数字符串，
 * 全程使用 BigInt，不经过 Number()，避免 2^53 以上的精度损失。
 */
export function parseBytesDecimal(input: string): bigint {
  const trimmed = input.trim()
  if (!/^-?\d+$/.test(trimmed)) {
    throw new TypeError(`非法的字节数十进制字符串: ${JSON.stringify(input)}`)
  }
  return BigInt(trimmed)
}

/**
 * 将字节数（十进制字符串或 bigint）格式化为人类可读形式。
 * 单位换算用 BigInt 整除与取余完成，小數部分按 fractionDigits 截断（不四舍五入）。
 */
export function formatBytes(
  input: string | bigint,
  fractionDigits = 2,
): string {
  let bytes = typeof input === 'bigint' ? input : parseBytesDecimal(input)
  let sign = ''
  if (bytes < 0n) {
    sign = '-'
    bytes = -bytes
  }

  let unitIndex = 0
  let scale = 1n
  while (unitIndex < UNITS.length - 1 && bytes >= scale * 1024n) {
    scale *= 1024n
    unitIndex += 1
  }

  const unit = UNITS[unitIndex]
  if (unitIndex === 0) return `${sign}${bytes.toString()} B`

  const integerPart = bytes / scale
  const remainder = bytes % scale
  if (fractionDigits <= 0) return `${sign}${integerPart.toString()} ${unit}`

  const factor = 10n ** BigInt(fractionDigits)
  const fraction = (remainder * factor) / scale
  return `${sign}${integerPart.toString()}.${fraction
    .toString()
    .padStart(fractionDigits, '0')} ${unit}`
}

/** 十进制字符串/ bigint 的千分位格式化，不经过 Number()。 */
export function formatDecimal(input: string | bigint): string {
  const value = typeof input === 'bigint' ? input : parseBytesDecimal(input)
  const negative = value < 0n
  const digits = (negative ? -value : value).toString()
  return `${negative ? '-' : ''}${digits.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}`
}
