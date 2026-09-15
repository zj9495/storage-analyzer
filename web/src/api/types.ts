import type { components } from './schema'

export type Schema = components['schemas']
export type BytesString = Schema['DecimalString']

export interface ApiEnvelope<T> {
  data: T
  meta: Record<string, unknown>
  request_id: string
}

export interface ListMeta {
  next_cursor: string | null
  page_size: number
  total_known: number | null
  truncated: boolean
  detail_available: boolean
}

export type Page<T> = ApiEnvelope<T[]> & { meta: ListMeta }
export type AdminUser = Schema['AdminUser']
export type Source = Schema['Source']
export type SourceUpdate = Schema['SourceUpdate']
export type MountRoot = Schema['MountRoot']
export type Volume = Schema['Volume']
export type VolumeSample = Schema['VolumeSample']
export type VolumeSampleResolution = 'raw' | 'day'
export type Profile = Schema['Profile']
export type ProfileConfig = Schema['ProfileConfig']
export type Job = Schema['Job']
/**
 * The report handlers expose the persisted column as `pinned`.
 * Keep this runtime type aligned with the API response instead of reading the
 * similarly named request field `report_pinned` from a response.
 */
export type ReportStatus = Schema['ReportSummary']['status']
export type ReportSummary = Omit<Schema['ReportSummary'], 'status'> & { status: ReportStatus }
export type ReportDetail = Omit<Schema['ReportDetail'], 'status'> & { status: ReportStatus }
export type FolderRow = Schema['FolderRow']
export type OwnerRow = Schema['OwnerRow']
export type CategoryRow = Schema['CategoryRow']
export type FileRow = Schema['FileRow']
export type RankingRow = Schema['RankingRow']
export type DuplicateGroup = Schema['DuplicateGroup']
export type DuplicateMember = Schema['DuplicateMember']
export type ExportRecord = Schema['ExportRecord']
export type CleanupPlan = Schema['CleanupPlan']
export type CleanupAction = Schema['CleanupAction']
export type QuarantineItem = Schema['QuarantineItem']
export interface CleanupPlanRequest {
  report_id: string
  groups: Array<{ group_id: string; keep_entry_ids: string[]; target_entry_ids: string[] }>
}
export type CategoryRuleset = Schema['CategoryRuleset']
export type CategoryRulesetInput = Schema['CategoryRulesetInput']
export type NotificationConfig = Schema['NotificationConfig']
export type NotificationConfigInput = Schema['NotificationConfigInput']
export type InternalNotification = Schema['InternalNotification']
export type StorageSettings = Schema['StorageSettings']
export type StorageSettingsInput = Schema['StorageSettingsInput']
export type RetentionSettings = Schema['RetentionSettings']
export type RetentionSettingsInput = Schema['RetentionSettingsInput']
export type DiagnosticInfo = Schema['DiagnosticInfo']
export type AuditEvent = Schema['AuditEvent']
export type ImportPreview = Schema['ImportPreview']
export type ComparisonResult = Schema['ComparisonResult']

export interface DuplicateGroupDetail {
  group: DuplicateGroup
  members: DuplicateMember[]
  truncated?: boolean
  truncation_reason?: string | null
}

export interface CompareRequest {
  other_report_id: string
  mode: 'aggregate' | 'files'
}

export interface CompareResponse {
  comparison_id: string
  job_id: string
  comparable?: boolean
  incompatibility_reasons?: string[]
}

export interface ExportRequest {
  section:
    | 'volume'
    | 'folders'
    | 'owners'
    | 'quota'
    | 'categories'
    | 'duplicates'
    | 'largest'
    | 'recently_modified'
    | 'least_accessed'
    | 'files'
    | 'full_report'
  format: 'csv' | 'json' | 'html' | 'zip'
  scope: 'current' | 'all'
  query?: Schema['QuerySpec']
}

export interface ExportCreateResponse {
  export_id: string
  job_id: string
}

export interface BackupResponse {
  job_id: string
  export_id?: string
}

export type BackupRequest =
  | { include_secrets?: false }
  | { include_secrets: true; secrets_passphrase: string }

export interface RestorePreviewRequest {
  backup_export_id: string
  secrets_passphrase?: string
}

export interface RestoreApplyRequest {
  preview_id: string
  reauth_token: string
  confirmation: string
  secrets_passphrase?: string
}

export interface RestorePreview {
  preview_id: string
  compatible: boolean
  config_version: number
  differences?: Array<{ key?: string; change?: 'added' | 'removed' | 'modified' }>
  warnings?: string[]
}
export type JobEvent = Schema['JobEvent']
export type QuerySpecContract = Schema['QuerySpec']
export type IdentityMapping = Schema['IdentityMapping']
export type QuotaRecord = Schema['QuotaRecord']
export type MetadataImportPayload = Schema['MetadataImportPayload']

export type Metric = Schema['Metric']
export type SortKey = Schema['SortKey']
export type ProfileSection = Schema['ProfileSection']

/**
 * 后端当前发送的 SSE 帧由事件名、Last-Event-ID 和 payload 组成。
 * created_at 不在当前 SSE data 帧中，因此不伪造时间戳；历史 HTTP
 * JobEvent schema 仍由 schema.d.ts 保留，实时帧使用这个归一化类型。
 */
export interface LiveJobEvent {
  job_id: string
  sequence: number
  type: string
  payload: Record<string, unknown>
  created_at?: Schema['DateTime']
}

export interface CompareJobResponse {
  comparison_id: string
  job_id: string
  comparable?: boolean
  incompatibility_reasons?: string[]
}

export interface ExportJobResponse {
  export_id: string
  job_id: string
}

export interface BackupJobResponse {
  job_id: string
  export_id?: string
}

export interface MetadataImportResult {
  applied: boolean
  identities_applied?: number
  source_links_applied?: number
  quotas_applied?: number
}

export interface ProbeResult {
  availability: Source['availability']
  capabilities: {
    atime_quality?: Source['atime_quality']
    filesystem_type?: string | null
    btrfs_shared_block_risk?: 'possible' | 'not_detected' | 'unknown'
    can_read_content?: boolean
    can_write?: boolean
    identity_observed?: boolean
    notes?: string[]
  }
}

export interface CleanupActionRequestResult {
  action_id: string
  job_id: string
}

export interface MeResponse {
  admin: AdminUser
  session_expires_at: Schema['DateTime']
  capabilities: {
    write_operations_allowed?: boolean
    write_operations_enabled?: boolean
    kernel_safe_writes?: boolean
    can_cleanup?: boolean
    initialized?: boolean
  }
}

export interface SetupStatusResponse {
  initialized: boolean
  can_initialize: boolean
}

export interface ReauthResponse {
  reauth_token: string
  expires_at: Schema['DateTime']
}
