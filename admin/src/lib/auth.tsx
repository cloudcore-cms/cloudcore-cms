import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { auth, User } from './api';

export interface AuthMethods {
  password: boolean;
  passkey: boolean;
  magicLink: boolean;
  github: boolean;
  google: boolean;
  cfAccess: boolean;
}

const DEFAULT_AUTH_METHODS: AuthMethods = {
  password: true,
  passkey: true,
  magicLink: false,
  github: false,
  google: false,
  cfAccess: false,
};

interface AuthContextType {
  user: User | null;
  loading: boolean;
  needsSetup: boolean | null; // null = unknown (still loading)
  authMethods: AuthMethods;
  envAvailable: AuthMethods; // What's available at infra level (env vars set)
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  refreshStatus: () => Promise<boolean>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [needsSetup, setNeedsSetup] = useState<boolean | null>(null);
  const [authMethods, setAuthMethods] = useState<AuthMethods>(DEFAULT_AUTH_METHODS);
  const [envAvailable, setEnvAvailable] = useState<AuthMethods>(DEFAULT_AUTH_METHODS);
  const navigate = useNavigate();
  const location = useLocation();

  const refresh = async () => {
    try {
      const { user } = await auth.me();
      setUser(user);
    } catch {
      setUser(null);
    }
  };

  const refreshStatus = async () => {
    try {
      const status = await auth.status();
      setNeedsSetup(status.needsSetup);
      if (status.authMethods) {
        setAuthMethods(status.authMethods);
      }
      if (status.envAvailable) {
        setEnvAvailable(status.envAvailable);
      }
      return status.needsSetup;
    } catch {
      // Don't assume setup is complete on error — keep current state
      // This prevents locking users out of setup due to network issues
      return needsSetup ?? true;
    }
  };

  useEffect(() => {
    const init = async () => {
      const setupRequired = await refreshStatus();
      if (!setupRequired) {
        await refresh();
      }
      setLoading(false);
    };
    init();
  }, []);

  // Redirect to setup if needed (except when already on setup page)
  useEffect(() => {
    if (!loading && needsSetup === true && location.pathname !== '/setup') {
      navigate('/setup', { replace: true });
    }
  }, [loading, needsSetup, location.pathname, navigate]);

  const login = async (email: string, password: string) => {
    const { user } = await auth.login(email, password);
    setUser(user);
    setNeedsSetup(false); // After login, setup is complete
    navigate('/');
  };

  const logout = async () => {
    await auth.logout();
    setUser(null);
    navigate('/login');
  };

  return (
    <AuthContext.Provider value={{ user, loading, needsSetup, authMethods, envAvailable, login, logout, refresh, refreshStatus }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading, needsSetup } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && !needsSetup && !user) {
      navigate('/login');
    }
  }, [user, loading, needsSetup, navigate]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  // If setup is needed or still loading status, don't render protected content
  if (needsSetup === true || needsSetup === null) {
    return null;
  }

  if (!user) {
    return null;
  }

  return <>{children}</>;
}
