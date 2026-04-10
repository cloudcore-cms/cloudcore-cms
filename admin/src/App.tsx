import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, RequireAuth } from './lib/auth';
import Layout from './components/Layout';
import Login from './routes/Login';
import Setup from './routes/Setup';
import Dashboard from './routes/Dashboard';
import ContentList from './routes/ContentList';
import ContentEdit from './routes/ContentEdit';
import MediaLibrary from './routes/MediaLibrary';
import Categories from './routes/Categories';
import Tags from './routes/Tags';
import Users from './routes/Users';
import Settings from './routes/Settings';
import Profile from './routes/Profile';

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/setup" element={<Setup />} />
        <Route
          path="/*"
          element={
            <RequireAuth>
              <Layout>
                <Routes>
                  <Route index element={<Dashboard />} />
                  <Route path="pages" element={<ContentList type="page" />} />
                  <Route path="posts" element={<ContentList type="post" />} />
                  <Route path="content/new" element={<ContentEdit />} />
                  <Route path="content/:id" element={<ContentEdit />} />
                  <Route path="media" element={<MediaLibrary />} />
                  <Route path="categories" element={<Categories />} />
                  <Route path="tags" element={<Tags />} />
                  <Route path="users" element={<Users />} />
                  <Route path="settings" element={<Settings />} />
                  <Route path="profile" element={<Profile />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </Layout>
            </RequireAuth>
          }
        />
      </Routes>
    </AuthProvider>
  );
}
