import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { profile, passkeys, oauth, OAuthConnection, PasskeyCredential } from '../lib/api';
import { useAuth } from '../lib/auth';
import { base64UrlToBuffer, bufferToBase64Url, isWebAuthnSupported } from '../lib/webauthn';
import {
  User,
  KeyRound,
  Lock,
  Link2,
  Save,
  Check,
  Trash2,
  Plus,
  Fingerprint,
  Loader2,
  Pencil,
  Github,
} from 'lucide-react';

export default function Profile() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const { user, refresh, authMethods } = useAuth();
  const [linkingProvider, setLinkingProvider] = useState<string | null>(null);

  // Handle OAuth link callback params
  const linkedProvider = searchParams.get('linked');
  const linkError = searchParams.get('error');

  useEffect(() => {
    if (linkedProvider || linkError) {
      // Refresh OAuth connections after successful link
      if (linkedProvider) {
        queryClient.invalidateQueries({ queryKey: ['oauth-connections'] });
      }
      // Clear URL params after showing
      const timer = setTimeout(() => {
        setSearchParams({}, { replace: true });
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [linkedProvider, linkError, queryClient, setSearchParams]);

  const handleLinkOAuth = async (provider: 'github' | 'google') => {
    setLinkingProvider(provider);
    try {
      const { url } = await oauth.link(provider);
      window.location.href = url;
    } catch (err) {
      setLinkingProvider(null);
    }
  };

  // ── Profile Info ──────────────────────────────
  const [profileForm, setProfileForm] = useState({
    name: '',
    email: '',
    bio: '',
    avatar: '',
  });
  const [profileSaved, setProfileSaved] = useState(false);

  useEffect(() => {
    if (user) {
      setProfileForm({
        name: user.name || '',
        email: user.email,
        bio: user.bio || '',
        avatar: user.avatar || '',
      });
    }
  }, [user]);

  const profileMutation = useMutation({
    mutationFn: (data: typeof profileForm) =>
      profile.update({
        name: data.name || null,
        email: data.email,
        bio: data.bio || null,
        avatar: data.avatar || null,
      }),
    onSuccess: () => {
      refresh();
      setProfileSaved(true);
      setTimeout(() => setProfileSaved(false), 2000);
    },
  });

  // ── Change Password ───────────────────────────
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [passwordError, setPasswordError] = useState('');
  const [passwordSaved, setPasswordSaved] = useState(false);

  const passwordMutation = useMutation({
    mutationFn: () =>
      profile.changePassword(passwordForm.currentPassword, passwordForm.newPassword),
    onSuccess: () => {
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
      setPasswordError('');
      setPasswordSaved(true);
      setTimeout(() => setPasswordSaved(false), 2000);
    },
    onError: (err) => {
      setPasswordError(err instanceof Error ? err.message : 'Failed to change password');
    },
  });

  const handlePasswordSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError('');
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setPasswordError('Passwords do not match');
      return;
    }
    if (passwordForm.newPassword.length < 12) {
      setPasswordError('Password must be at least 12 characters');
      return;
    }
    passwordMutation.mutate();
  };

  // ── Passkeys ──────────────────────────────────
  const webAuthnSupported = isWebAuthnSupported();
  const [passkeyName, setPasskeyName] = useState('');
  const [registeringPasskey, setRegisteringPasskey] = useState(false);
  const [passkeyError, setPasskeyError] = useState('');
  const [editingPasskey, setEditingPasskey] = useState<string | null>(null);
  const [editPasskeyName, setEditPasskeyName] = useState('');

  const { data: passkeyData, isLoading: passkeysLoading } = useQuery({
    queryKey: ['passkeys'],
    queryFn: passkeys.list,
  });

  const deletePasskeyMutation = useMutation({
    mutationFn: passkeys.delete,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['passkeys'] }),
  });

  const renamePasskeyMutation = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) =>
      passkeys.update(id, { name }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passkeys'] });
      setEditingPasskey(null);
    },
  });

  const handleRegisterPasskey = async () => {
    if (!webAuthnSupported) return;
    setPasskeyError('');
    setRegisteringPasskey(true);

    try {
      const options = await passkeys.getRegisterOptions();
      const publicKey: PublicKeyCredentialCreationOptions = {
        challenge: base64UrlToBuffer(options.challenge),
        rp: options.rp,
        user: {
          id: base64UrlToBuffer(options.user.id),
          name: options.user.name,
          displayName: options.user.displayName,
        },
        pubKeyCredParams: options.pubKeyCredParams as PublicKeyCredentialParameters[],
        authenticatorSelection: {
          residentKey: options.authenticatorSelection.residentKey as ResidentKeyRequirement,
          userVerification: options.authenticatorSelection.userVerification as UserVerificationRequirement,
        },
        timeout: options.timeout,
        attestation: options.attestation as AttestationConveyancePreference,
        excludeCredentials: options.excludeCredentials.map((c) => ({
          id: base64UrlToBuffer(c.id),
          type: 'public-key' as const,
        })),
      };

      const credential = (await navigator.credentials.create({
        publicKey,
      })) as PublicKeyCredential;

      if (!credential) throw new Error('No credential returned');

      const response = credential.response as AuthenticatorAttestationResponse;

      await passkeys.verifyRegister({
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        response: {
          clientDataJSON: bufferToBase64Url(response.clientDataJSON),
          attestationObject: bufferToBase64Url(response.attestationObject),
        },
        type: 'public-key',
        name: passkeyName || undefined,
      });

      setPasskeyName('');
      queryClient.invalidateQueries({ queryKey: ['passkeys'] });
    } catch (err) {
      if (err instanceof Error && err.name === 'NotAllowedError') {
        setPasskeyError('Registration was cancelled');
      } else {
        setPasskeyError(err instanceof Error ? err.message : 'Failed to register passkey');
      }
    } finally {
      setRegisteringPasskey(false);
    }
  };

  // ── OAuth Connections ─────────────────────────
  const { data: oauthData, isLoading: oauthLoading } = useQuery({
    queryKey: ['oauth-connections'],
    queryFn: profile.getOAuthConnections,
    enabled: authMethods.github || authMethods.google,
  });

  const unlinkOAuthMutation = useMutation({
    mutationFn: profile.unlinkOAuth,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['oauth-connections'] }),
  });

  // ── Render ────────────────────────────────────
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Profile</h1>

      <div className="max-w-2xl space-y-6">
        {/* Profile Info */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            profileMutation.mutate(profileForm);
          }}
        >
          <div className="card space-y-4">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <User className="w-5 h-5" /> Profile Information
            </h2>

            <div>
              <label className="label">Name</label>
              <input
                type="text"
                value={profileForm.name}
                onChange={(e) => setProfileForm({ ...profileForm, name: e.target.value })}
                className="input mt-1"
                placeholder="Your name"
              />
            </div>

            <div>
              <label className="label">Email</label>
              <input
                type="email"
                value={profileForm.email}
                onChange={(e) => setProfileForm({ ...profileForm, email: e.target.value })}
                className="input mt-1"
              />
            </div>

            <div>
              <label className="label">Bio</label>
              <textarea
                value={profileForm.bio}
                onChange={(e) => setProfileForm({ ...profileForm, bio: e.target.value })}
                className="textarea mt-1"
                rows={3}
                placeholder="A short bio..."
              />
            </div>

            <div>
              <label className="label">Avatar URL</label>
              <input
                type="url"
                value={profileForm.avatar}
                onChange={(e) => setProfileForm({ ...profileForm, avatar: e.target.value })}
                className="input mt-1"
                placeholder="https://..."
              />
            </div>

            {profileMutation.isError && (
              <p className="text-sm text-red-600">
                {profileMutation.error instanceof Error ? profileMutation.error.message : 'Failed to save'}
              </p>
            )}

            <div className="pt-4 border-t border-gray-200">
              <button type="submit" disabled={profileMutation.isPending} className="btn btn-primary">
                {profileSaved ? (
                  <><Check className="w-4 h-4 mr-1" /> Saved</>
                ) : (
                  <><Save className="w-4 h-4 mr-1" /> {profileMutation.isPending ? 'Saving...' : 'Save Profile'}</>
                )}
              </button>
            </div>
          </div>
        </form>

        {/* Change Password */}
        <form onSubmit={handlePasswordSubmit}>
          <div className="card space-y-4">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <Lock className="w-5 h-5" /> Change Password
            </h2>

            <div>
              <label className="label">Current Password</label>
              <input
                type="password"
                value={passwordForm.currentPassword}
                onChange={(e) => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })}
                className="input mt-1"
                required
              />
            </div>

            <div>
              <label className="label">New Password</label>
              <input
                type="password"
                value={passwordForm.newPassword}
                onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
                className="input mt-1"
                required
                minLength={12}
              />
              <p className="mt-1 text-xs text-gray-500">
                Min 12 chars, uppercase, lowercase, number, and special character
              </p>
            </div>

            <div>
              <label className="label">Confirm New Password</label>
              <input
                type="password"
                value={passwordForm.confirmPassword}
                onChange={(e) => setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })}
                className="input mt-1"
                required
              />
            </div>

            {passwordError && (
              <p className="text-sm text-red-600">{passwordError}</p>
            )}

            <div className="pt-4 border-t border-gray-200">
              <button type="submit" disabled={passwordMutation.isPending} className="btn btn-primary">
                {passwordSaved ? (
                  <><Check className="w-4 h-4 mr-1" /> Password Changed</>
                ) : (
                  <><KeyRound className="w-4 h-4 mr-1" /> {passwordMutation.isPending ? 'Changing...' : 'Change Password'}</>
                )}
              </button>
            </div>
          </div>
        </form>

        {/* Passkeys */}
        {authMethods.passkey && (
          <div className="card space-y-4">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <Fingerprint className="w-5 h-5" /> Passkeys
            </h2>
            <p className="text-sm text-gray-500">
              Use a fingerprint, face scan, or security key to sign in without a password.
            </p>

            {passkeysLoading ? (
              <div className="flex justify-center py-4">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
              </div>
            ) : (
              <>
                {passkeyData?.items && passkeyData.items.length > 0 ? (
                  <div className="divide-y divide-gray-100">
                    {passkeyData.items.map((pk: PasskeyCredential) => (
                      <div key={pk.id} className="flex items-center justify-between py-3">
                        <div>
                          {editingPasskey === pk.id ? (
                            <div className="flex items-center gap-2">
                              <input
                                type="text"
                                value={editPasskeyName}
                                onChange={(e) => setEditPasskeyName(e.target.value)}
                                className="input input-sm"
                                autoFocus
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') {
                                    renamePasskeyMutation.mutate({ id: pk.id, name: editPasskeyName });
                                  } else if (e.key === 'Escape') {
                                    setEditingPasskey(null);
                                  }
                                }}
                              />
                              <button
                                onClick={() => renamePasskeyMutation.mutate({ id: pk.id, name: editPasskeyName })}
                                className="btn btn-sm btn-primary"
                              >
                                Save
                              </button>
                            </div>
                          ) : (
                            <>
                              <p className="text-sm font-medium text-gray-900 flex items-center gap-1">
                                {pk.name}
                                <button
                                  onClick={() => {
                                    setEditingPasskey(pk.id);
                                    setEditPasskeyName(pk.name);
                                  }}
                                  className="text-gray-400 hover:text-gray-600"
                                >
                                  <Pencil className="w-3 h-3" />
                                </button>
                              </p>
                              <p className="text-xs text-gray-500">
                                {pk.deviceType} {pk.backedUp && '(backed up)'} &middot;{' '}
                                Created {new Date(pk.createdAt).toLocaleDateString()}
                                {pk.lastUsedAt && (
                                  <> &middot; Last used {new Date(pk.lastUsedAt).toLocaleDateString()}</>
                                )}
                              </p>
                            </>
                          )}
                        </div>
                        <button
                          onClick={() => {
                            if (confirm('Delete this passkey?')) {
                              deletePasskeyMutation.mutate(pk.id);
                            }
                          }}
                          className="p-1 text-gray-400 hover:text-red-600"
                          title="Delete passkey"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-gray-400 py-2">No passkeys registered yet.</p>
                )}
              </>
            )}

            {passkeyError && (
              <p className="text-sm text-red-600">{passkeyError}</p>
            )}

            {webAuthnSupported && (
              <div className="flex items-center gap-2 pt-2">
                <input
                  type="text"
                  value={passkeyName}
                  onChange={(e) => setPasskeyName(e.target.value)}
                  className="input flex-1"
                  placeholder="Passkey name (optional)"
                />
                <button
                  onClick={handleRegisterPasskey}
                  disabled={registeringPasskey}
                  className="btn btn-primary flex items-center gap-1"
                >
                  {registeringPasskey ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Plus className="w-4 h-4" />
                  )}
                  {registeringPasskey ? 'Registering...' : 'Add Passkey'}
                </button>
              </div>
            )}

            {!webAuthnSupported && (
              <p className="text-sm text-amber-600">
                WebAuthn is not supported in this browser. Use a modern browser to register passkeys.
              </p>
            )}
          </div>
        )}

        {/* OAuth Connections */}
        {(authMethods.github || authMethods.google) && (
          <div className="card space-y-4">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <Link2 className="w-5 h-5" /> Linked Accounts
            </h2>

            {linkedProvider && (
              <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-md text-sm">
                Successfully linked your {linkedProvider} account.
              </div>
            )}
            {linkError && (
              <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-md text-sm">
                {decodeURIComponent(linkError)}
              </div>
            )}

            {oauthLoading ? (
              <div className="flex justify-center py-4">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
              </div>
            ) : (
              <>
                {oauthData?.items && oauthData.items.length > 0 && (
                  <div className="divide-y divide-gray-100">
                    {oauthData.items.map((conn: OAuthConnection) => (
                      <div key={conn.id} className="flex items-center justify-between py-3">
                        <div className="flex items-center gap-3">
                          {conn.provider === 'github' ? (
                            <Github className="w-5 h-5 text-gray-700" />
                          ) : (
                            <span className="text-sm font-medium text-gray-700 capitalize">{conn.provider}</span>
                          )}
                          <div>
                            <p className="text-sm font-medium text-gray-900 capitalize">{conn.provider}</p>
                            {conn.providerEmail && (
                              <p className="text-xs text-gray-500">{conn.providerEmail}</p>
                            )}
                          </div>
                        </div>
                        <button
                          onClick={() => {
                            if (confirm(`Unlink ${conn.provider} account?`)) {
                              unlinkOAuthMutation.mutate(conn.id);
                            }
                          }}
                          disabled={unlinkOAuthMutation.isPending}
                          className="text-sm text-red-600 hover:text-red-800"
                        >
                          Unlink
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {/* Link buttons for providers not yet linked */}
                <div className="flex gap-2 pt-2">
                  {authMethods.github && !oauthData?.items?.some((c: OAuthConnection) => c.provider === 'github') && (
                    <button
                      onClick={() => handleLinkOAuth('github')}
                      disabled={linkingProvider === 'github'}
                      className="btn btn-sm flex items-center gap-1.5 bg-gray-800 text-white hover:bg-gray-900"
                    >
                      {linkingProvider === 'github' ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <Github className="w-4 h-4" />
                      )}
                      Link GitHub
                    </button>
                  )}
                  {authMethods.google && !oauthData?.items?.some((c: OAuthConnection) => c.provider === 'google') && (
                    <button
                      onClick={() => handleLinkOAuth('google')}
                      disabled={linkingProvider === 'google'}
                      className="btn btn-sm flex items-center gap-1.5 border border-gray-300 text-gray-700 hover:bg-gray-50"
                    >
                      {linkingProvider === 'google' ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <span className="text-sm">G</span>
                      )}
                      Link Google
                    </button>
                  )}
                </div>
              </>
            )}

            {unlinkOAuthMutation.isError && (
              <p className="text-sm text-red-600">
                {unlinkOAuthMutation.error instanceof Error ? unlinkOAuthMutation.error.message : 'Failed to unlink'}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
