import { createBrowserRouter, Navigate } from 'react-router-dom'
import { Root } from './Root'
import { RequireAuth } from './guards'
import { AppLayout } from './layout'
import { NotFoundPage } from './NotFoundPage'
import { LoginPage } from '../features/auth/LoginPage'
import { ChangePasswordPage } from '../features/auth/ChangePasswordPage'
import { OverviewPage } from '../features/overview/OverviewPage'
import { SourcesPage } from '../features/sources/SourcesPage'
import { ProfilesPage } from '../features/profiles/ProfilesPage'
import { JobsPage } from '../features/jobs/JobsPage'
import { ReportsPage } from '../features/reports/ReportsPage'
import { ReportDetailPage } from '../features/reports/ReportDetailPage'
import { CleanupPage } from '../features/cleanup/CleanupPage'
import { SettingsPage } from '../features/settings/SettingsPage'
import { DiagnosticsPage } from '../features/diagnostics/DiagnosticsPage'

export const router = createBrowserRouter([
  {
    element: <Root />,
    children: [
      { path: '/login', element: <LoginPage /> },
      {
        path: '/change-password',
        element: (
          <RequireAuth>
            <ChangePasswordPage />
          </RequireAuth>
        ),
      },
      {
        path: '/',
        element: (
          <RequireAuth>
            <AppLayout />
          </RequireAuth>
        ),
        children: [
          { index: true, element: <Navigate to="/overview" replace /> },
          { path: 'overview', element: <OverviewPage /> },
          { path: 'sources', element: <SourcesPage /> },
          { path: 'profiles', element: <ProfilesPage /> },
          { path: 'jobs', element: <JobsPage /> },
          { path: 'reports', element: <ReportsPage /> },
          { path: 'reports/:id', element: <ReportDetailPage /> },
          { path: 'cleanup', element: <CleanupPage /> },
          { path: 'settings', element: <SettingsPage /> },
          { path: 'diagnostics', element: <DiagnosticsPage /> },
        ],
      },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
])
