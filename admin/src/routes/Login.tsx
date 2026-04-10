import { useState, useEffect } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { passkeys, oauth, magicLinks } from '../lib/api';
import { base64UrlToBuffer, bufferToBase64Url, isWebAuthnSupported } from '../lib/webauthn';
import { Fingerprint, Github, Mail, Loader2 } from 'lucide-react';

export default function Login() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login, refresh, needsSetup, authMethods } = useAuth();
  const [step, setStep] = useState<'email' | 'credentials'>('email');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [magicLinkLoading, setMagicLinkLoading] = useState(false);
  const [oauthLoading, setOauthLoading] = useState<string | null>(null);
  const [webAuthnSupported, setWebAuthnSupported] = useState(false);
  const [userHasPasskeys, setUserHasPasskeys] = useState(false);
  const [checkingEmail, setCheckingEmail] = useState(false);

  // Check if WebAuthn is supported
  useEffect(() => {
    setWebAuthnSupported(isWebAuthnSupported());
  }, []);

  // Handle OAuth callback
  useEffect(() => {
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const oauthError = searchParams.get('error');
    const provider = searchParams.get('provider') as 'github' | 'google' | null;

    if (oauthError) {
      setError(`OAuth error: ${searchParams.get('error_description') || oauthError}`);
      // Clear URL params
      window.history.replaceState({}, '', '/login');
      return;
    }

    if (code && state && provider) {
      setOauthLoading(provider);
      oauth.callback(provider, code, state)
        .then(() => {
          refresh();
          navigate('/');
        })
        .catch((err) => {
          setError(err instanceof Error ? err.message : 'OAuth login failed');
        })
        .finally(() => {
          setOauthLoading(null);
          // Clear URL params
          window.history.replaceState({}, '', '/login');
        });
    }

    // Handle magic link verification
    const magicToken = searchParams.get('magic_token');
    if (magicToken) {
      setLoading(true);
      magicLinks.verify(magicToken)
        .then(() => {
          refresh();
          navigate('/');
        })
        .catch((err) => {
          setError(err instanceof Error ? err.message : 'Magic link verification failed');
        })
        .finally(() => {
          setLoading(false);
          window.history.replaceState({}, '', '/login');
        });
    }
  }, [searchParams, navigate, refresh]);

  // Step 1: Check email for passkey availability
  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    setError('');
    setCheckingEmail(true);

    try {
      if (authMethods.passkey && webAuthnSupported) {
        const result = await passkeys.checkForEmail(email);
        setUserHasPasskeys(result.hasPasskeys);
      }
      setStep('credentials');
    } catch {
      // If check fails, still proceed to credentials step
      setStep('credentials');
    } finally {
      setCheckingEmail(false);
    }
  };

  // Step 2: Password login
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handlePasskeyLogin = async () => {
    if (!webAuthnSupported) {
      setError('WebAuthn is not supported in this browser');
      return;
    }

    setError('');
    setPasskeyLoading(true);

    try {
      // Get authentication options from server
      const options = await passkeys.getAuthOptions(email || undefined);

      // Prepare credential request options
      const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
        challenge: base64UrlToBuffer(options.challenge),
        rpId: options.rpId,
        timeout: options.timeout,
        userVerification: options.userVerification,
        allowCredentials: options.allowCredentials?.map((cred) => ({
          id: base64UrlToBuffer(cred.id),
          type: 'public-key' as const,
        })),
      };

      // Request credential from authenticator
      const credential = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('No credential returned');
      }

      const response = credential.response as AuthenticatorAssertionResponse;

      // Send to server for verification
      await passkeys.verifyAuth({
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        response: {
          clientDataJSON: bufferToBase64Url(response.clientDataJSON),
          authenticatorData: bufferToBase64Url(response.authenticatorData),
          signature: bufferToBase64Url(response.signature),
          userHandle: response.userHandle
            ? bufferToBase64Url(response.userHandle)
            : undefined,
        },
        type: 'public-key',
      });

      // Refresh auth state and navigate
      await refresh();
      navigate('/');
    } catch (err) {
      if (err instanceof Error) {
        if (err.name === 'NotAllowedError') {
          setError('Passkey authentication was cancelled');
        } else if (err.name === 'SecurityError') {
          setError('Security error - please ensure you are on a secure connection');
        } else {
          setError(err.message || 'Passkey authentication failed');
        }
      } else {
        setError('Passkey authentication failed');
      }
    } finally {
      setPasskeyLoading(false);
    }
  };

  const handleOAuthLogin = async (provider: 'github' | 'google') => {
    setError('');
    setOauthLoading(provider);

    try {
      const { url } = await oauth.authorize(provider);
      // Redirect to OAuth provider
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : `${provider} login failed`);
      setOauthLoading(null);
    }
  };


  const handleMagicLinkFromEmail = async () => {
    setError('');
    setMagicLinkLoading(true);
    try {
      const result = await magicLinks.request(email);
      setSuccess(result.message || 'Check your email for the magic link!');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send magic link');
    } finally {
      setMagicLinkLoading(false);
    }
  };

  const hasAlternativeMethods = authMethods.github || authMethods.google;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h1 className="text-center text-3xl font-bold text-gray-900">
            Cloudcore CMS
          </h1>
          <h2 className="mt-2 text-center text-sm text-gray-600">
            Sign in to your account
          </h2>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-md text-sm">
            {error}
          </div>
        )}

        {success && (
          <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-md text-sm">
            {success}
          </div>
        )}

        {/* OAuth Buttons — always visible, don't need email first */}
        {hasAlternativeMethods && (
          <>
            <div className="flex gap-3">
              {authMethods.github && (
                <button
                  type="button"
                  onClick={() => handleOAuthLogin('github')}
                  disabled={!!oauthLoading || loading}
                  className="btn flex-1 flex items-center justify-center gap-2 bg-gray-800 text-white hover:bg-gray-900 disabled:opacity-50"
                >
                  {oauthLoading === 'github' ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : (
                    <Github className="w-5 h-5" />
                  )}
                  GitHub
                </button>
              )}
              {authMethods.google && (
                <button
                  type="button"
                  onClick={() => handleOAuthLogin('google')}
                  disabled={!!oauthLoading || loading}
                  className="btn flex-1 flex items-center justify-center gap-2 bg-white border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {oauthLoading === 'google' ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : (
                    <svg className="w-5 h-5" viewBox="0 0 24 24">
                      <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                      <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                      <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                      <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                    </svg>
                  )}
                  Google
                </button>
              )}
            </div>

            {(authMethods.password || authMethods.passkey || authMethods.magicLink) && (
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-300" />
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="px-2 bg-gray-50 text-gray-500">Or continue with email</span>
                </div>
              </div>
            )}
          </>
        )}

        {/* Step 1: Email */}
        {step === 'email' && (authMethods.password || authMethods.passkey || authMethods.magicLink) && (
          <form onSubmit={handleEmailSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="label">Email</label>
              <input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="input mt-1"
                placeholder="admin@example.com"
                autoFocus
              />
            </div>
            <button
              type="submit"
              disabled={checkingEmail || !email}
              className="btn btn-primary w-full"
            >
              {checkingEmail ? (
                <><Loader2 className="w-4 h-4 animate-spin mr-1" /> Checking...</>
              ) : (
                'Continue'
              )}
            </button>
          </form>
        )}

        {/* Step 2: Credentials (after email entered) */}
        {step === 'credentials' && (
          <div className="space-y-4">
            {/* Show which email */}
            <div className="flex items-center justify-between bg-gray-100 rounded-md px-3 py-2">
              <span className="text-sm text-gray-700">{email}</span>
              <button
                type="button"
                onClick={() => { setStep('email'); setUserHasPasskeys(false); setPassword(''); setError(''); }}
                className="text-xs text-primary hover:underline"
              >
                Change
              </button>
            </div>

            {/* Passkey — only if user has registered passkeys */}
            {authMethods.passkey && webAuthnSupported && userHasPasskeys && (
              <button
                type="button"
                onClick={handlePasskeyLogin}
                disabled={passkeyLoading || loading}
                className="btn w-full flex items-center justify-center gap-2 bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50"
              >
                {passkeyLoading ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <Fingerprint className="w-5 h-5" />
                )}
                {passkeyLoading ? 'Authenticating...' : 'Sign in with Passkey'}
              </button>
            )}

            {/* Password */}
            {authMethods.password && (
              <>
                {authMethods.passkey && webAuthnSupported && userHasPasskeys && (
                  <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                      <div className="w-full border-t border-gray-300" />
                    </div>
                    <div className="relative flex justify-center text-sm">
                      <span className="px-2 bg-gray-50 text-gray-500">or use password</span>
                    </div>
                  </div>
                )}
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label htmlFor="password" className="label">Password</label>
                    <input
                      id="password"
                      type="password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="input mt-1"
                      autoFocus={!userHasPasskeys}
                    />
                  </div>
                  <button type="submit" disabled={loading} className="btn btn-primary w-full">
                    {loading ? 'Signing in...' : 'Sign in'}
                  </button>
                </form>
              </>
            )}

            {/* Magic Link */}
            {authMethods.magicLink && (
              <button
                type="button"
                onClick={handleMagicLinkFromEmail}
                disabled={magicLinkLoading}
                className="w-full text-center text-sm text-primary hover:underline flex items-center justify-center gap-1"
              >
                {magicLinkLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Mail className="w-4 h-4" />
                )}
                {magicLinkLoading ? 'Sending...' : 'Send me a Magic Link instead'}
              </button>
            )}
          </div>
        )}

        {/* Setup link */}
        {needsSetup === true && (
          <p className="text-center text-sm text-gray-600">
            First time?{' '}
            <Link to="/setup" className="text-primary hover:underline">
              Create admin account
            </Link>
          </p>
        )}
      </div>
    </div>
  );
}
