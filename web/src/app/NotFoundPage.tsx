import { Button, Result } from 'antd'
import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <Result
      status="404"
      title="页面不存在"
      subTitle="请检查地址是否正确。"
      extra={
        <Link to="/overview">
          <Button type="primary">返回总览</Button>
        </Link>
      }
    />
  )
}
