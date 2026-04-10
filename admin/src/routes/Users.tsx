import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Navigate } from 'react-router-dom';
import { users, User, audit, AuditLogEntry } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Plus, Pencil, Trash2, X, Shield, ShieldCheck, UserX, Info, ChevronDown, ChevronUp, Clock, LogIn, LogOut, AlertTriangle, KeyRound, Monitor, Globe } from 'lucide-react';

const roleLabels = {
  admin: 'Admin',
  editor: 'Editor',
  contributor: 'Contributor',
};

const roleColors = {
  admin: 'bg-purple-100 text-purple-800',
  editor: 'bg-blue-100 text-blue-800',
  contributor: 'bg-gray-100 text-gray-800',
};

export default function Users() {
  const queryClient = useQueryClient();
  const { user: currentUser } = useAuth();
  const [editingId, setEditingId] = useState<string | null>(null);
  const [showNewForm, setShowNewForm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAuditLog, setShowAuditLog] = useState(false);

  // Only admins can access user management
  if (currentUser?.role !== 'admin') {
    return <Navigate to="/" replace />;
  }

  const { data, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: users.list,
  });

  const { data: auditData, isLoading: auditLoading } = useQuery({
    queryKey: ['audit', 'logins'],
    queryFn: () => audit.logins({ limit: 50 }),
    enabled: showAuditLog,
  });

  const createMutation = useMutation({
    mutationFn: users.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setShowNewForm(false);
      setError(null);
    },
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof users.update>[1] }) =>
      users.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setEditingId(null);
      setError(null);
    },
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: users.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setError(null);
    },
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Users</h1>
        <button
          onClick={() => {
            setShowNewForm(true);
            setError(null);
          }}
          className="btn btn-primary btn-sm"
        >
          <Plus className="w-4 h-4 mr-1" /> New User
        </button>
      </div>

      {/* Role descriptions */}
      <div className="card bg-blue-50 border-blue-200">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
          <div>
            <h3 className="font-medium text-blue-900 mb-2">User Role Permissions</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div>
                <div className="flex items-center gap-1.5 mb-1">
                  <ShieldCheck className="w-4 h-4 text-purple-600" />
                  <span className="font-medium text-purple-800">Admin</span>
                </div>
                <ul className="text-blue-800 space-y-0.5 ml-5">
                  <li>Full access to all features</li>
                  <li>Manage users and site settings</li>
                  <li>Publish, delete, and manage all content</li>
                </ul>
              </div>
              <div>
                <div className="flex items-center gap-1.5 mb-1">
                  <Shield className="w-4 h-4 text-blue-600" />
                  <span className="font-medium text-blue-800">Editor</span>
                </div>
                <ul className="text-blue-800 space-y-0.5 ml-5">
                  <li>Create and edit all content</li>
                  <li>Publish and unpublish content</li>
                  <li>Manage media and categories</li>
                </ul>
              </div>
              <div>
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="w-4 h-4 rounded-full bg-gray-400 flex items-center justify-center text-white text-xs">C</span>
                  <span className="font-medium text-gray-700">Contributor</span>
                </div>
                <ul className="text-blue-800 space-y-0.5 ml-5">
                  <li>Create and edit own drafts</li>
                  <li>Cannot publish content</li>
                  <li>Cannot edit published content</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-md text-sm">
          {error}
          <button
            onClick={() => setError(null)}
            className="float-right text-red-500 hover:text-red-700"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      <div className="card">
        {isLoading ? (
          <div className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : data?.items.length === 0 && !showNewForm ? (
          <div className="text-center py-8">
            <p className="text-gray-500">No users found</p>
            <button
              onClick={() => setShowNewForm(true)}
              className="text-primary hover:underline text-sm mt-2"
            >
              Create your first user
            </button>
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {/* New user form */}
            {showNewForm && (
              <div className="py-4 px-4 bg-gray-50">
                <NewUserForm
                  onSave={(userData) => {
                    createMutation.mutate(userData);
                  }}
                  onCancel={() => {
                    setShowNewForm(false);
                    setError(null);
                  }}
                  isLoading={createMutation.isPending}
                />
              </div>
            )}

            {data?.items.map((user) => {
              const isEditing = editingId === user.id;
              const isCurrentUser = user.id === currentUser?.id;

              return (
                <div
                  key={user.id}
                  className="flex items-center justify-between py-4 px-4 hover:bg-gray-50"
                >
                  {isEditing ? (
                    <EditUserForm
                      user={user}
                      isCurrentUser={isCurrentUser}
                      onSave={(userData) => {
                        updateMutation.mutate({ id: user.id, data: userData });
                      }}
                      onCancel={() => {
                        setEditingId(null);
                        setError(null);
                      }}
                      isLoading={updateMutation.isPending}
                    />
                  ) : (
                    <>
                      <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-full bg-gray-200 flex items-center justify-center text-gray-500">
                          {user.name?.charAt(0).toUpperCase() || user.email.charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-gray-900">
                              {user.name || user.email}
                            </span>
                            {isCurrentUser && (
                              <span className="text-xs text-gray-500">(you)</span>
                            )}
                            {user.isActive === false && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
                                <UserX className="w-3 h-3 mr-1" />
                                Inactive
                              </span>
                            )}
                          </div>
                          <div className="text-sm text-gray-500">{user.email}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                            roleColors[user.role]
                          }`}
                        >
                          {user.role === 'admin' && <ShieldCheck className="w-3 h-3 mr-1" />}
                          {user.role === 'editor' && <Shield className="w-3 h-3 mr-1" />}
                          {roleLabels[user.role]}
                        </span>
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => {
                              setEditingId(user.id);
                              setError(null);
                            }}
                            className="p-2 text-gray-400 hover:text-gray-600"
                            title="Edit"
                          >
                            <Pencil className="w-4 h-4" />
                          </button>
                          {!isCurrentUser && (
                            <button
                              onClick={() => {
                                if (confirm(`Delete user ${user.email}?`)) {
                                  deleteMutation.mutate(user.id);
                                }
                              }}
                              className="p-2 text-gray-400 hover:text-red-600"
                              title="Delete"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </div>
                    </>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Login Audit Log Section */}
      <div className="card">
        <button
          onClick={() => setShowAuditLog(!showAuditLog)}
          className="w-full flex items-center justify-between py-2 text-left"
        >
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-gray-500" />
            <span className="font-medium text-gray-900">Login Activity Log</span>
          </div>
          {showAuditLog ? (
            <ChevronUp className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          )}
        </button>

        {showAuditLog && (
          <div className="mt-4 border-t pt-4">
            {auditLoading ? (
              <div className="flex justify-center py-8">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
              </div>
            ) : auditData?.items.length === 0 ? (
              <p className="text-center text-gray-500 py-4">No login activity recorded</p>
            ) : (
              <div className="space-y-2">
                {auditData?.items.map((entry) => (
                  <LoginAuditRow key={entry.id} entry={entry} />
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function LoginAuditRow({ entry }: { entry: AuditLogEntry }) {
  const getActionIcon = (action: string) => {
    switch (action) {
      case 'login':
        return <LogIn className="w-4 h-4 text-green-600" />;
      case 'logout':
        return <LogOut className="w-4 h-4 text-blue-600" />;
      case 'login_failed':
        return <AlertTriangle className="w-4 h-4 text-red-600" />;
      case 'passkey_login':
      case 'passkey_register':
        return <KeyRound className="w-4 h-4 text-purple-600" />;
      default:
        return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const getActionLabel = (action: string) => {
    switch (action) {
      case 'login':
        return 'Logged in';
      case 'logout':
        return 'Logged out';
      case 'login_failed':
        return 'Failed login attempt';
      case 'passkey_login':
        return 'Passkey login';
      case 'passkey_register':
        return 'Registered passkey';
      case 'session_expired':
        return 'Session expired';
      default:
        return action;
    }
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'login':
      case 'passkey_login':
        return 'bg-green-50 text-green-700';
      case 'logout':
        return 'bg-blue-50 text-blue-700';
      case 'login_failed':
        return 'bg-red-50 text-red-700';
      case 'passkey_register':
        return 'bg-purple-50 text-purple-700';
      default:
        return 'bg-gray-50 text-gray-700';
    }
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleString();
  };

  const parseUserAgent = (ua: string | null) => {
    if (!ua) return 'Unknown device';
    // Simple parsing - extract browser and OS
    if (ua.includes('Chrome')) return 'Chrome';
    if (ua.includes('Firefox')) return 'Firefox';
    if (ua.includes('Safari')) return 'Safari';
    if (ua.includes('Edge')) return 'Edge';
    return 'Browser';
  };

  return (
    <div className="flex items-center justify-between py-2 px-3 rounded-lg bg-gray-50 hover:bg-gray-100 transition-colors">
      <div className="flex items-center gap-3">
        <div className={`p-2 rounded-full ${getActionColor(entry.action)}`}>
          {getActionIcon(entry.action)}
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-medium text-gray-900">
              {entry.userEmail || 'Unknown user'}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full ${getActionColor(entry.action)}`}>
              {getActionLabel(entry.action)}
            </span>
          </div>
          <div className="flex items-center gap-3 text-xs text-gray-500 mt-0.5">
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {formatDate(entry.createdAt)}
            </span>
            {entry.ipAddress && (
              <span className="flex items-center gap-1">
                <Globe className="w-3 h-3" />
                {entry.ipAddress}
              </span>
            )}
            {entry.userAgent && (
              <span className="flex items-center gap-1">
                <Monitor className="w-3 h-3" />
                {parseUserAgent(entry.userAgent)}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function NewUserForm({
  onSave,
  onCancel,
  isLoading,
}: {
  onSave: (data: { email: string; password: string; name?: string; role?: 'admin' | 'editor' | 'contributor' }) => void;
  onCancel: () => void;
  isLoading: boolean;
}) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState<'admin' | 'editor' | 'contributor'>('contributor');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (email.trim() && password.trim()) {
      onSave({
        email: email.trim(),
        password: password.trim(),
        name: name.trim() || undefined,
        role,
      });
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="label">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="input"
            placeholder="user@example.com"
            required
            autoFocus
          />
        </div>
        <div>
          <label className="label">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="input"
            placeholder="John Doe"
          />
        </div>
        <div>
          <label className="label">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="input"
            placeholder="Min 12 chars, mixed case, number, symbol"
            required
            minLength={12}
          />
          <p className="mt-1 text-xs text-gray-500">
            Must contain uppercase, lowercase, number, and special character
          </p>
        </div>
        <div>
          <label className="label">Role</label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as 'admin' | 'editor' | 'contributor')}
            className="input"
          >
            <option value="contributor">Contributor</option>
            <option value="editor">Editor</option>
            <option value="admin">Admin</option>
          </select>
        </div>
      </div>
      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="btn btn-secondary btn-sm"
          disabled={isLoading}
        >
          Cancel
        </button>
        <button type="submit" className="btn btn-primary btn-sm" disabled={isLoading}>
          {isLoading ? 'Creating...' : 'Create User'}
        </button>
      </div>
    </form>
  );
}

function EditUserForm({
  user,
  isCurrentUser,
  onSave,
  onCancel,
  isLoading,
}: {
  user: User;
  isCurrentUser: boolean;
  onSave: (data: { name?: string; email?: string; role?: 'admin' | 'editor' | 'contributor'; isActive?: boolean; password?: string }) => void;
  onCancel: () => void;
  isLoading: boolean;
}) {
  const [email, setEmail] = useState(user.email);
  const [name, setName] = useState(user.name || '');
  const [role, setRole] = useState<'admin' | 'editor' | 'contributor'>(user.role);
  const [isActive, setIsActive] = useState(user.isActive !== false);
  const [password, setPassword] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const updates: Parameters<typeof onSave>[0] = {};

    if (email.trim() !== user.email) updates.email = email.trim();
    if (name.trim() !== (user.name || '')) updates.name = name.trim();
    if (role !== user.role && !isCurrentUser) updates.role = role;
    if (isActive !== (user.isActive !== false) && !isCurrentUser) updates.isActive = isActive;
    if (password.trim()) updates.password = password.trim();

    if (Object.keys(updates).length > 0) {
      onSave(updates);
    } else {
      onCancel();
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex-1 space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="label">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="input"
            required
          />
        </div>
        <div>
          <label className="label">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="input"
          />
        </div>
        <div>
          <label className="label">New Password (leave blank to keep)</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="input"
            placeholder="Leave blank to keep current"
            minLength={12}
          />
        </div>
        <div>
          <label className="label">Role</label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as 'admin' | 'editor' | 'contributor')}
            className="input"
            disabled={isCurrentUser}
          >
            <option value="contributor">Contributor</option>
            <option value="editor">Editor</option>
            <option value="admin">Admin</option>
          </select>
          {isCurrentUser && (
            <p className="mt-1 text-xs text-gray-500">You cannot change your own role</p>
          )}
        </div>
        {!isCurrentUser && (
          <div className="col-span-2">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={isActive}
                onChange={(e) => setIsActive(e.target.checked)}
                className="rounded border-gray-300 text-primary focus:ring-primary"
              />
              <span className="text-sm text-gray-700">Active account</span>
            </label>
          </div>
        )}
      </div>
      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="btn btn-secondary btn-sm"
          disabled={isLoading}
        >
          Cancel
        </button>
        <button type="submit" className="btn btn-primary btn-sm" disabled={isLoading}>
          {isLoading ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </form>
  );
}
