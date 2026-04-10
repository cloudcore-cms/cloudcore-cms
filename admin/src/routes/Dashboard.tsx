import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { content, media } from '../lib/api';
import { FileText, Newspaper, Image, Plus } from 'lucide-react';

export default function Dashboard() {
  const { data: pages } = useQuery({
    queryKey: ['content', 'pages'],
    queryFn: () => content.list({ type: 'page', limit: 5 }),
  });

  const { data: posts } = useQuery({
    queryKey: ['content', 'posts'],
    queryFn: () => content.list({ type: 'post', limit: 5 }),
  });

  const { data: mediaItems } = useQuery({
    queryKey: ['media'],
    queryFn: () => media.list({ limit: 5 }),
  });

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <div className="flex gap-2">
          <Link
            to="/content/new?type=page"
            className="btn btn-secondary btn-sm"
          >
            <Plus className="w-4 h-4 mr-1" /> New Page
          </Link>
          <Link
            to="/content/new?type=post"
            className="btn btn-primary btn-sm"
          >
            <Plus className="w-4 h-4 mr-1" /> New Post
          </Link>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card">
          <div className="flex items-center">
            <div className="p-3 bg-blue-100 rounded-lg">
              <FileText className="w-6 h-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Pages</p>
              <p className="text-2xl font-semibold text-gray-900">
                {pages?.pagination.total ?? 0}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="p-3 bg-green-100 rounded-lg">
              <Newspaper className="w-6 h-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Posts</p>
              <p className="text-2xl font-semibold text-gray-900">
                {posts?.pagination.total ?? 0}
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="p-3 bg-purple-100 rounded-lg">
              <Image className="w-6 h-6 text-purple-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Media</p>
              <p className="text-2xl font-semibold text-gray-900">
                {mediaItems?.pagination.total ?? 0}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent content */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Recent Pages */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Recent Pages</h2>
            <Link to="/pages" className="text-sm text-primary hover:underline">
              View all
            </Link>
          </div>
          {pages?.items.length === 0 ? (
            <p className="text-gray-500 text-sm">No pages yet</p>
          ) : (
            <ul className="space-y-2">
              {pages?.items.map((page) => (
                <li key={page.id}>
                  <Link
                    to={`/content/${page.id}`}
                    className="flex items-center justify-between py-2 hover:bg-gray-50 -mx-2 px-2 rounded"
                  >
                    <span className="text-sm font-medium text-gray-900 truncate">
                      {page.title}
                    </span>
                    <span
                      className={`text-xs px-2 py-1 rounded ${
                        page.status === 'published'
                          ? 'bg-green-100 text-green-700'
                          : 'bg-yellow-100 text-yellow-700'
                      }`}
                    >
                      {page.status}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Recent Posts */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Recent Posts</h2>
            <Link to="/posts" className="text-sm text-primary hover:underline">
              View all
            </Link>
          </div>
          {posts?.items.length === 0 ? (
            <p className="text-gray-500 text-sm">No posts yet</p>
          ) : (
            <ul className="space-y-2">
              {posts?.items.map((post) => (
                <li key={post.id}>
                  <Link
                    to={`/content/${post.id}`}
                    className="flex items-center justify-between py-2 hover:bg-gray-50 -mx-2 px-2 rounded"
                  >
                    <span className="text-sm font-medium text-gray-900 truncate">
                      {post.title}
                    </span>
                    <span
                      className={`text-xs px-2 py-1 rounded ${
                        post.status === 'published'
                          ? 'bg-green-100 text-green-700'
                          : 'bg-yellow-100 text-yellow-700'
                      }`}
                    >
                      {post.status}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
