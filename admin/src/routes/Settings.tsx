import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Navigate } from 'react-router-dom';
import { settings } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Save, Check, Shield } from 'lucide-react';

interface SettingsForm {
  siteName: string;
  siteDescription: string;
  siteUrl: string;
  postsPerPage: number;
}

export default function Settings() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const [form, setForm] = useState<SettingsForm>({
    siteName: '',
    siteDescription: '',
    siteUrl: '',
    postsPerPage: 10,
  });
  const [saved, setSaved] = useState(false);

  // Only admins can access settings
  if (user?.role !== 'admin') {
    return <Navigate to="/" replace />;
  }

  const { data, isLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: settings.getAll,
  });

  useEffect(() => {
    if (data) {
      setForm({
        siteName: (data.siteName as string) || '',
        siteDescription: (data.siteDescription as string) || '',
        siteUrl: (data.siteUrl as string) || '',
        postsPerPage: (data.postsPerPage as number) || 10,
      });
    }
  }, [data]);

  const saveMutation = useMutation({
    mutationFn: async (values: SettingsForm) => {
      await Promise.all([
        settings.set('siteName', values.siteName),
        settings.set('siteDescription', values.siteDescription),
        settings.set('siteUrl', values.siteUrl),
        settings.set('postsPerPage', values.postsPerPage),
      ]);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    saveMutation.mutate(form);
  };

  if (isLoading) {
    return (
      <div className="flex justify-center py-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
      </div>

      <form onSubmit={handleSubmit} className="max-w-2xl">
        <div className="card space-y-6">
          <h2 className="text-lg font-semibold text-gray-900">General</h2>

          <div>
            <label className="label">Site Name</label>
            <input
              type="text"
              value={form.siteName}
              onChange={(e) => setForm({ ...form, siteName: e.target.value })}
              className="input mt-1"
              placeholder="My Website"
            />
          </div>

          <div>
            <label className="label">Site Description</label>
            <textarea
              value={form.siteDescription}
              onChange={(e) => setForm({ ...form, siteDescription: e.target.value })}
              className="textarea mt-1"
              placeholder="A brief description of your site..."
              rows={3}
            />
          </div>

          <div>
            <label className="label">Site URL</label>
            <input
              type="url"
              value={form.siteUrl}
              onChange={(e) => setForm({ ...form, siteUrl: e.target.value })}
              className="input mt-1"
              placeholder="https://example.com"
            />
            <p className="text-xs text-gray-500 mt-1">
              The full URL where your site is hosted
            </p>
          </div>

          <div>
            <label className="label">Posts Per Page</label>
            <input
              type="number"
              value={form.postsPerPage}
              onChange={(e) => setForm({ ...form, postsPerPage: parseInt(e.target.value) || 10 })}
              className="input mt-1 w-24"
              min={1}
              max={100}
            />
          </div>

          <div className="pt-4 border-t border-gray-200">
            <button
              type="submit"
              disabled={saveMutation.isPending}
              className="btn btn-primary"
            >
              {saved ? (
                <>
                  <Check className="w-4 h-4 mr-1" /> Saved
                </>
              ) : (
                <>
                  <Save className="w-4 h-4 mr-1" />
                  {saveMutation.isPending ? 'Saving...' : 'Save Settings'}
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Authentication Methods */}
      <AuthSettingsSection />

      {/* API Info */}
      <div className="max-w-2xl">
        <div className="card">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">API Information</h2>
          <div className="space-y-3 text-sm">
            <div>
              <span className="text-gray-500">API Base URL:</span>
              <code className="ml-2 px-2 py-1 bg-gray-100 rounded text-gray-900">
                {window.location.origin}/api/v1
              </code>
            </div>
            <div>
              <span className="text-gray-500">Documentation:</span>
              <span className="ml-2 text-gray-900">
                See <code className="px-1 bg-gray-100 rounded">AGENTS.md</code> for API reference
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Auth settings toggles
const AUTH_METHODS = [
  { key: 'auth.password', field: 'password', label: 'Password Login', description: 'Allow users to sign in with email and password' },
  { key: 'auth.passkey', field: 'passkey', label: 'Passkey / WebAuthn', description: 'Allow users to sign in with fingerprint, face scan, or security key' },
  { key: 'auth.magicLink', field: 'magicLink', label: 'Magic Link (Email)', description: 'Send a one-time login link via email' },
  { key: 'auth.github', field: 'github', label: 'GitHub OAuth', description: 'Allow users to sign in with their GitHub account' },
  { key: 'auth.google', field: 'google', label: 'Google OAuth', description: 'Allow users to sign in with their Google account' },
  { key: 'auth.cfAccess', field: 'cfAccess', label: 'Cloudflare Access', description: 'Allow users to sign in via Cloudflare Access' },
] as const;

function AuthSettingsSection() {
  const queryClient = useQueryClient();
  const { envAvailable, refreshStatus } = useAuth();
  const [authToggles, setAuthToggles] = useState<Record<string, boolean>>({});
  const [authError, setAuthError] = useState('');
  const [authSaved, setAuthSaved] = useState(false);

  const { data } = useQuery({
    queryKey: ['settings'],
    queryFn: settings.getAll,
  });

  useEffect(() => {
    if (data) {
      const toggles: Record<string, boolean> = {};
      for (const method of AUTH_METHODS) {
        // Use DB value if set, otherwise default to true (enabled)
        const dbValue = data[method.key];
        toggles[method.field] = typeof dbValue === 'boolean' ? dbValue : true;
      }
      setAuthToggles(toggles);
    }
  }, [data]);

  const saveMutation = useMutation({
    mutationFn: async (toggles: Record<string, boolean>) => {
      const results = [];
      for (const method of AUTH_METHODS) {
        results.push(settings.set(method.key, toggles[method.field]));
      }
      await Promise.all(results);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      refreshStatus();
      setAuthError('');
      setAuthSaved(true);
      setTimeout(() => setAuthSaved(false), 2000);
    },
    onError: (err) => {
      setAuthError(err instanceof Error ? err.message : 'Failed to save auth settings');
    },
  });

  return (
    <div className="max-w-2xl">
      <div className="card space-y-4">
        <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
          <Shield className="w-5 h-5" /> Authentication Methods
        </h2>
        <p className="text-sm text-gray-500">
          Enable or disable sign-in methods. At least one method must remain enabled.
        </p>

        <div className="divide-y divide-gray-100">
          {AUTH_METHODS.map((method) => {
            const isAvailable = envAvailable[method.field as keyof typeof envAvailable];
            const isEnabled = authToggles[method.field] ?? true;

            return (
              <div key={method.key} className="flex items-center justify-between py-3">
                <div className="flex-1">
                  <p className="text-sm font-medium text-gray-900">{method.label}</p>
                  <p className="text-xs text-gray-500">{method.description}</p>
                  {!isAvailable && (
                    <p className="text-xs text-amber-600 mt-0.5">
                      Not configured — set environment variables to enable
                    </p>
                  )}
                </div>
                <label className="relative inline-flex items-center cursor-pointer ml-4">
                  <input
                    type="checkbox"
                    checked={isEnabled && isAvailable}
                    disabled={!isAvailable}
                    onChange={(e) => {
                      setAuthToggles({ ...authToggles, [method.field]: e.target.checked });
                    }}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary/50 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary peer-disabled:opacity-50 peer-disabled:cursor-not-allowed"></div>
                </label>
              </div>
            );
          })}
        </div>

        {authError && (
          <p className="text-sm text-red-600">{authError}</p>
        )}

        <div className="pt-4 border-t border-gray-200">
          <button
            onClick={() => saveMutation.mutate(authToggles)}
            disabled={saveMutation.isPending}
            className="btn btn-primary"
          >
            {authSaved ? (
              <><Check className="w-4 h-4 mr-1" /> Saved</>
            ) : (
              <><Save className="w-4 h-4 mr-1" /> {saveMutation.isPending ? 'Saving...' : 'Save Auth Settings'}</>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
