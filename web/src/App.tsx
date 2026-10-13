import React, { Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router';
import { useAuth } from './features/auth';
import { ProtectedRoute, PublicRoute, AdminRoute, Layout, RequireAccountSetup } from './components/layout';
import {
    SessionTimeoutWarning,
    AbsoluteSessionExpiryWarning,
    Spinner,
    ErrorBoundary,
    RouteErrorBoundary,
} from './components/ui';
import { ROUTES } from './constants';

// ── Page-level lazy bundles ───────────────────────────────────────────────────
// Each route gets its own chunk; the core shell (guards, layout, stores) stays
// in the initial bundle and is never re-fetched.

const LoginPage = React.lazy(() => import('./pages/auth/LoginPage').then((m) => ({ default: m.LoginPage })));
const SetupPage = React.lazy(() => import('./pages/auth/SetupPage').then((m) => ({ default: m.SetupPage })));
const SSOCompletePage = React.lazy(() =>
    import('./pages/auth/SSOCompletePage').then((m) => ({ default: m.SSOCompletePage }))
);

const DashboardPage = React.lazy(() =>
    import('./pages/dashboard/DashboardPage').then((m) => ({ default: m.DashboardPage }))
);

const SecretsListPage = React.lazy(() =>
    import('./pages/secrets/SecretsListPage').then((m) => ({ default: m.SecretsListPage }))
);
const DynamicSecretsPage = React.lazy(() => import('./pages/secrets/DynamicSecretsPage'));
const RotationPoliciesPage = React.lazy(() =>
    import('./pages/secrets/RotationPoliciesPage').then((m) => ({ default: m.RotationPoliciesPage }))
);
const SecretExpiryPage = React.lazy(() =>
    import('./pages/secrets/SecretExpiryPage').then((m) => ({ default: m.SecretExpiryPage }))
);
const SecretsHealthPage = React.lazy(() =>
    import('./pages/secrets/SecretsHealthPage').then((m) => ({ default: m.SecretsHealthPage }))
);
const UsageAnalyticsPage = React.lazy(() =>
    import('./pages/secrets/UsageAnalyticsPage').then((m) => ({ default: m.UsageAnalyticsPage }))
);

const ProjectsListPage = React.lazy(() =>
    import('./pages/projects/ProjectsListPage').then((m) => ({ default: m.ProjectsListPage }))
);
const ProjectDetailPage = React.lazy(() =>
    import('./pages/projects/ProjectDetailPage').then((m) => ({ default: m.ProjectDetailPage }))
);

const AuditLogPage = React.lazy(() => import('./pages/audit/AuditLogPage').then((m) => ({ default: m.AuditLogPage })));
const SharingManagementPage = React.lazy(() =>
    import('./pages/sharing').then((m) => ({ default: m.SharingManagementPage }))
);
const ProfilePage = React.lazy(() => import('./pages/profile').then((m) => ({ default: m.ProfilePage })));

const AdminPage = React.lazy(() => import('./pages/admin/AdminPage').then((m) => ({ default: m.AdminPage })));
const BillingPage = React.lazy(() => import('./pages/billing/BillingPage').then((m) => ({ default: m.BillingPage })));
const UserDetailPage = React.lazy(() =>
    import('./pages/admin/UserDetailPage').then((m) => ({ default: m.UserDetailPage }))
);
const RolesPoliciesPage = React.lazy(() =>
    import('./pages/admin/RolesPoliciesPage').then((m) => ({ default: m.RolesPoliciesPage }))
);
const GroupsPage = React.lazy(() => import('./pages/admin/GroupsPage').then((m) => ({ default: m.GroupsPage })));
const MachineIdentitiesPage = React.lazy(() =>
    import('./pages/admin/MachineIdentitiesPage').then((m) => ({ default: m.MachineIdentitiesPage }))
);
const NotificationChannelsPage = React.lazy(() =>
    import('./pages/admin/NotificationChannelsPage').then((m) => ({ default: m.NotificationChannelsPage }))
);

const AppearancePage = React.lazy(() =>
    import('./pages/settings/AppearancePage').then((m) => ({ default: m.AppearancePage }))
);
const SystemHealthPage = React.lazy(() =>
    import('./pages/settings/SystemHealthPage').then((m) => ({ default: m.SystemHealthPage }))
);
const AuthenticationPage = React.lazy(() =>
    import('./pages/settings/AuthenticationPage').then((m) => ({ default: m.AuthenticationPage }))
);
const EncryptionPage = React.lazy(() =>
    import('./pages/settings/EncryptionPage').then((m) => ({ default: m.EncryptionPage }))
);
const LicensePage = React.lazy(() => import('./pages/settings/LicensePage').then((m) => ({ default: m.LicensePage })));
const CompliancePage = React.lazy(() =>
    import('./pages/compliance/CompliancePage').then((m) => ({ default: m.CompliancePage }))
);
const KeyorixConnectPage = React.lazy(() =>
    import('./pages/integrations/KeyorixConnectPage').then((m) => ({ default: m.KeyorixConnectPage }))
);
const SdksPage = React.lazy(() => import('./pages/integrations/SdksPage').then((m) => ({ default: m.SdksPage })));
const RoadmapPage = React.lazy(() => import('./pages/roadmap/RoadmapPage').then((m) => ({ default: m.RoadmapPage })));

// ── Route fallback ────────────────────────────────────────────────────────────

const PageSpinner = () => (
    <div className="min-h-screen flex items-center justify-center">
        <Spinner size="lg" />
    </div>
);

const NotFoundPage = () => (
    <div className="py-20 flex items-center justify-center">
        <div className="text-center">
            <h1 className="text-4xl font-bold mb-4 text-[var(--text-primary)]">404</h1>
            <p className="mb-4 text-[var(--text-secondary)]">Page not found</p>
            <a href={ROUTES.DASHBOARD} className="text-[var(--accent)]">
                Go to Dashboard
            </a>
        </div>
    </div>
);

function App() {
    useAuth();

    return (
        <ErrorBoundary>
            <Suspense fallback={<PageSpinner />}>
                <Routes>
                    {/* Public Routes */}
                    <Route
                        path={ROUTES.LOGIN}
                        element={
                            <PublicRoute>
                                <LoginPage />
                            </PublicRoute>
                        }
                    />

                    <Route path="/auth/setup/:token" element={<SetupPage />} />
                    <Route path="/auth/sso/complete" element={<SSOCompletePage />} />

                    {/* Authenticated routes */}
                    <Route
                        element={
                            <ProtectedRoute>
                                <RequireAccountSetup>
                                    <Layout>
                                        <RouteErrorBoundary>
                                            <Routes>
                                                <Route path={ROUTES.DASHBOARD} element={<DashboardPage />} />
                                                <Route path={ROUTES.SECRETS} element={<SecretsListPage />} />
                                                <Route path="/secrets/dynamic" element={<DynamicSecretsPage />} />
                                                <Route path="/secrets/rotation" element={<RotationPoliciesPage />} />
                                                <Route path="/secrets/expiry" element={<SecretExpiryPage />} />
                                                <Route path="/secrets/health" element={<SecretsHealthPage />} />
                                                <Route path="/secrets/usage" element={<UsageAnalyticsPage />} />
                                                <Route path={ROUTES.PROJECTS} element={<ProjectsListPage />} />
                                                <Route path="/projects/:id/*" element={<ProjectDetailPage />} />
                                                <Route path={ROUTES.AUDIT} element={<AuditLogPage />} />
                                                <Route path={ROUTES.SHARING} element={<SharingManagementPage />} />
                                                <Route path={ROUTES.PROFILE} element={<ProfilePage />} />
                                                <Route
                                                    path={ROUTES.ADMIN_USERS}
                                                    element={
                                                        <AdminRoute>
                                                            <AdminPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path="/admin/users/:id"
                                                    element={
                                                        <AdminRoute>
                                                            <UserDetailPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path={ROUTES.ADMIN}
                                                    element={
                                                        <AdminRoute>
                                                            <AdminPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path={ROUTES.ADMIN_BILLING}
                                                    element={
                                                        <AdminRoute>
                                                            <BillingPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path="/admin/roles"
                                                    element={
                                                        <AdminRoute>
                                                            <RolesPoliciesPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path="/admin/groups"
                                                    element={
                                                        <AdminRoute>
                                                            <GroupsPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                {/* Legacy service-account URLs: retired (see docs/adr-113-retire-legacy-service-accounts.md)
                                                    in favour of machine identities -- redirect rather than 404 for anyone with
                                                    an old bookmark/link. */}
                                                <Route
                                                    path="/admin/service-accounts"
                                                    element={
                                                        <AdminRoute>
                                                            <Navigate to="/admin/machine-identities" replace />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path="/admin/api-tokens"
                                                    element={
                                                        <AdminRoute>
                                                            <Navigate to="/admin/machine-identities" replace />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path="/admin/machine-identities"
                                                    element={
                                                        <AdminRoute>
                                                            <MachineIdentitiesPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path={ROUTES.ADMIN_NOTIFICATION_CHANNELS}
                                                    element={
                                                        <AdminRoute>
                                                            <NotificationChannelsPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route path="/settings/appearance" element={<AppearancePage />} />
                                                <Route
                                                    path={ROUTES.SETTINGS_HEALTH}
                                                    element={
                                                        <AdminRoute>
                                                            <SystemHealthPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path={ROUTES.SETTINGS_AUTH}
                                                    element={
                                                        <AdminRoute>
                                                            <AuthenticationPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path={ROUTES.SETTINGS_ENCRYPTION}
                                                    element={
                                                        <AdminRoute>
                                                            <EncryptionPage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route
                                                    path={ROUTES.SETTINGS_LICENSE}
                                                    element={
                                                        <AdminRoute>
                                                            <LicensePage />
                                                        </AdminRoute>
                                                    }
                                                />
                                                <Route path={ROUTES.COMPLIANCE} element={<CompliancePage />} />
                                                <Route path={ROUTES.CONNECT} element={<KeyorixConnectPage />} />
                                                <Route path={ROUTES.SDKS_CLI} element={<SdksPage />} />
                                                <Route path={ROUTES.ROADMAP} element={<RoadmapPage />} />
                                                {/* Catch all. It must live here, not as a top-level `*`
                                                    sibling: this layout route's `/*` has the same splat
                                                    score and is declared first, so a top-level `*` is never
                                                    matched and an unknown URL rendered an empty Layout. An
                                                    unauthenticated visitor still gets ProtectedRoute's
                                                    redirect to /login before reaching this. */}
                                                <Route path="*" element={<NotFoundPage />} />
                                            </Routes>
                                        </RouteErrorBoundary>
                                    </Layout>
                                </RequireAccountSetup>
                            </ProtectedRoute>
                        }
                        path="/*"
                    />

                    {/* Default redirect */}
                    <Route path={ROUTES.HOME} element={<Navigate to={ROUTES.DASHBOARD} replace />} />
                </Routes>
            </Suspense>

            <SessionTimeoutWarning />
            <AbsoluteSessionExpiryWarning />
        </ErrorBoundary>
    );
}

export default App;
