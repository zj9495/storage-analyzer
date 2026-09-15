import { useEffect, useRef } from 'react'
import * as echarts from 'echarts'
import type { ECharts, EChartsOption } from 'echarts'

/**
 * 生命周期安全的 ECharts 挂载 Hook（spec 15.8）：
 * - 挂载时 init，option 变化时 setOption
 * - ResizeObserver 监听容器尺寸并 resize
 * - 卸载时 disconnect + dispose，避免实例/监听器泄漏
 */
export function useECharts<T extends HTMLElement = HTMLDivElement>(
  option: EChartsOption | null,
) {
  const containerRef = useRef<T | null>(null)
  const chartRef = useRef<ECharts | null>(null)
  const optionRef = useRef(option)
  optionRef.current = option

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    const chart = echarts.init(container)
    chartRef.current = chart
    if (optionRef.current) chart.setOption(optionRef.current)

    const observer = new ResizeObserver(() => {
      chart.resize()
    })
    observer.observe(container)

    return () => {
      observer.disconnect()
      chart.dispose()
      chartRef.current = null
    }
  }, [])

  useEffect(() => {
    if (option && chartRef.current) {
      chartRef.current.setOption(option, { notMerge: true })
    }
  }, [option])

  return containerRef
}
