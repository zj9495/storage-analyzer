import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Tag } from 'antd'
import { api } from '../../api/client'
import type { MountRoot, ProbeResult, Source, SourceUpdate, Volume } from '../../api/types'
import { MutationError } from '../../components/MutationError'
import { PageHeader } from '../../components/PageHeader'
import { PagePagination } from '../../components/PagePagination'
import { QueryState } from '../../components/QueryState'

export interface SourceForm { name: string; mount_key: string; relative_root: string; volume_id?: string | null; storage_kind: Source['storage_kind']; read_policy: Source['read_policy']; write_enabled: boolean; protected: boolean; exclusions?: string[] }
export interface VolumeForm { name: string; capacity_source_id: string }

// eslint-disable-next-line react-refresh/only-export-components
export function sourceUpdatePayload(values: SourceForm): SourceUpdate {
  return { name: values.name, read_policy: values.read_policy, write_enabled: values.write_enabled, exclusions: values.exclusions }
}
export function volumeUpdatePayload(values: VolumeForm): { name: string; capacity_source_id: string } {
  return { name: values.name, capacity_source_id: values.capacity_source_id }
}
export function SourcesPage() {
  const queryClient = useQueryClient()
  const [sourceOpen, setSourceOpen] = useState(false)
  const [volumeOpen, setVolumeOpen] = useState(false)
  const [editing, setEditing] = useState<Source>()
  const [editingVolume, setEditingVolume] = useState<Volume>()
  const [probe, setProbe] = useState<ProbeResult>()
  const [sourceCursor, setSourceCursor] = useState<string>()
  const [volumeCursor, setVolumeCursor] = useState<string>()
  const [sourceForm] = Form.useForm<SourceForm>()
  const [volumeForm] = Form.useForm<VolumeForm>()
  const sources = useQuery({ queryKey: ['sources', 'list', sourceCursor], queryFn: ({ signal }) => api.getPage<Source>('/api/v1/sources', { signal, query: { cursor: sourceCursor, page_size: 50 } }) })
  const volumes = useQuery({ queryKey: ['volumes', 'list', volumeCursor], queryFn: ({ signal }) => api.getPage<Volume>('/api/v1/volumes', { signal, query: { cursor: volumeCursor, page_size: 50 } }) })
  const mounts = useQuery({ queryKey: ['mounts'], queryFn: async ({ signal }) => (await api.get<MountRoot[]>('/api/v1/mounts', { signal })).data })
  const saveSource = useMutation({ mutationFn: (values: SourceForm) => editing ? api.patch<Source>(`/api/v1/sources/${encodeURIComponent(editing.id)}`, sourceUpdatePayload(values)) : api.post<Source>('/api/v1/sources', values), onSuccess: async () => { setSourceOpen(false); setEditing(undefined); await queryClient.invalidateQueries({ queryKey: ['sources'] }) } })
  const removeSource = useMutation({ mutationFn: (id: string) => api.delete(`/api/v1/sources/${encodeURIComponent(id)}`), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['sources'] }) })
  const probeSource = useMutation({ mutationFn: (id: string) => api.post<ProbeResult>(`/api/v1/sources/${encodeURIComponent(id)}/probe`), onSuccess: (response) => { setProbe(response.data); void queryClient.invalidateQueries({ queryKey: ['sources'] }) } })
  const confirmIdentity = useMutation({ mutationFn: (source: Source) => api.post<Source>(`/api/v1/sources/${encodeURIComponent(source.id)}/confirm-identity`, { expected_identity_epoch: source.identity_epoch }), onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['sources'] }) })
  const saveVolume = useMutation({ mutationFn: (values: VolumeForm) => editingVolume ? api.patch<Volume>(`/api/v1/volumes/${encodeURIComponent(editingVolume.id)}`, volumeUpdatePayload(values)) : api.post<Volume>('/api/v1/volumes', values), onSuccess: async () => { setVolumeOpen(false); setEditingVolume(undefined); await queryClient.invalidateQueries({ queryKey: ['volumes'] }) } })
  const openSource = (source?: Source) => { setEditing(source); sourceForm.resetFields(); sourceForm.setFieldsValue(source ? { name: source.name, mount_key: source.mount_key, relative_root: source.relative_root, volume_id: source.volume_id, storage_kind: source.storage_kind, read_policy: source.read_policy, write_enabled: source.write_enabled, protected: source.protected, exclusions: source.exclusions } : { relative_root: '', storage_kind: 'local', read_policy: 'metadata_only', write_enabled: false, protected: false }); setSourceOpen(true) }
  const openVolume = (volume?: Volume) => { setEditingVolume(volume); volumeForm.resetFields(); if (volume !== undefined) volumeForm.setFieldsValue({ name: volume.name, capacity_source_id: volume.capacity_source_id ?? undefined }); setVolumeOpen(true) }

  return <div><PageHeader title="数据源" description="源列表、身份、文件系统、权限与可用性" extra={<Space><Button type="primary" onClick={() => openSource()}>登记数据源</Button><Button onClick={() => openVolume()}>登记卷</Button></Space>} />
    <MutationError error={saveSource.error} /><MutationError error={removeSource.error} /><MutationError error={probeSource.error} /><MutationError error={confirmIdentity.error} /><MutationError error={saveVolume.error} />
    {probe ? <Alert type="info" showIcon closable onClose={() => setProbe(undefined)} message={`探测结果：${probe.availability}`} description={probe.capabilities.notes?.join('；')} style={{ marginBottom: 16 }} /> : null}
    <QueryState query={sources}>{(page) => <><Card title="数据源"><Table<Source> rowKey="id" dataSource={page.data} pagination={false} locale={{ emptyText: '尚未登记任何数据源' }} columns={[{ title: '名称', dataIndex: 'name' }, { title: '挂载键', dataIndex: 'mount_key' }, { title: '相对路径', dataIndex: 'relative_root' }, { title: '存储类型', dataIndex: 'storage_kind' }, { title: '读取策略', dataIndex: 'read_policy' }, { title: '可用性', dataIndex: 'availability', render: (value: Source['availability']) => <Tag>{value}</Tag> }, { title: '身份', dataIndex: 'identity_status', render: (value: Source['identity_status']) => <Tag>{value}</Tag> }, { title: '操作', render: (_, source) => <Space wrap><Button size="small" loading={probeSource.isPending && probeSource.variables === source.id} onClick={() => probeSource.mutate(source.id)}>只读探测</Button>{source.identity_status === 'changed' ? <Button size="small" onClick={() => confirmIdentity.mutate(source)}>确认新身份</Button> : null}<Button size="small" onClick={() => openSource(source)}>编辑</Button><Popconfirm title="停用数据源？历史报告会保留。" onConfirm={() => removeSource.mutate(source.id)} okText="停用" cancelText="取消"><Button danger size="small">停用</Button></Popconfirm></Space> }]} /></Card><PagePagination meta={page.meta} loading={sources.isFetching} onNext={setSourceCursor} /></>}</QueryState>
    <QueryState query={volumes}>{(page) => <Card title="卷容量采样" style={{ marginTop: 16 }}><Table<Volume> rowKey="id" dataSource={page.data} pagination={false} locale={{ emptyText: '尚未登记卷' }} columns={[{ title: '名称', dataIndex: 'name' }, { title: '状态', dataIndex: 'status', render: (value: Volume['status']) => <Tag>{value}</Tag> }, { title: '容量源', dataIndex: 'capacity_source_id' }, { title: '最近采样', render: (_, volume) => volume.last_sample?.sample_time }, { title: '已用', render: (_, volume) => volume.last_sample?.used_bytes }, { title: '操作', render: (_, volume) => <Button size="small" onClick={() => openVolume(volume)}>编辑</Button> }]} /><PagePagination meta={page.meta} loading={volumes.isFetching} onNext={setVolumeCursor} /></Card>}</QueryState>
    <Modal title={editing ? '编辑数据源' : '登记数据源'} open={sourceOpen} destroyOnClose onCancel={() => { setSourceOpen(false); setEditing(undefined) }} onOk={() => sourceForm.submit()} confirmLoading={saveSource.isPending}><Form<SourceForm> form={sourceForm} layout="vertical" onFinish={(values) => saveSource.mutate(values)}><Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item><Form.Item name="mount_key" label="批准挂载" rules={[{ required: true }]}><Select disabled={editing !== undefined} loading={mounts.isPending} options={mounts.data?.map((mount) => ({ value: mount.key, label: mount.key }))} /></Form.Item><Form.Item name="relative_root" label="挂载内相对路径"><Input disabled={editing !== undefined} /></Form.Item><Form.Item name="volume_id" label="容量卷"><Select disabled={editing !== undefined} allowClear options={volumes.data?.data.map((volume) => ({ value: volume.id, label: volume.name }))} /></Form.Item><Form.Item name="storage_kind" label="存储类型"><Select disabled={editing !== undefined} options={['local', 'remote', 'tiered', 'unknown'].map((value) => ({ value, label: value }))} /></Form.Item><Form.Item name="exclusions" label="排除规则"><Select mode="tags" placeholder="输入 glob 后按 Enter" /></Form.Item><Form.Item name="read_policy" label="读取策略"><Select options={[{ value: 'metadata_only', label: '仅元数据' }, { value: 'content_allowed', label: '允许读取内容' }]} /></Form.Item><Space><Form.Item name="write_enabled" label="允许写入" valuePropName="checked"><Switch /></Form.Item><Form.Item name="protected" label="受保护源" valuePropName="checked"><Switch disabled={editing !== undefined} /></Form.Item></Space></Form></Modal>
    <Modal title={editingVolume ? '编辑卷' : '登记卷'} open={volumeOpen} destroyOnClose onCancel={() => { setVolumeOpen(false); setEditingVolume(undefined) }} onOk={() => volumeForm.submit()} confirmLoading={saveVolume.isPending}><Form<VolumeForm> form={volumeForm} layout="vertical" onFinish={(values) => saveVolume.mutate(values)}><Form.Item name="name" label="卷名称" rules={[{ required: true }]}><Input /></Form.Item><Form.Item name="capacity_source_id" label="容量采样源" rules={[{ required: true }]}><Select options={sources.data?.data.map((source) => ({ value: source.id, label: source.name }))} /></Form.Item></Form></Modal>
  </div>
}
