import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { content } from '../lib/api';
import { useAuth } from '../lib/auth';
import { Plus, Pencil, Trash2, Eye, EyeOff } from 'lucide-react';

interface ContentListProps {
  type: 'page' | 'post';
}

export default function ContentList({ type }: ContentListProps) {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const [status, setStatus] = useState<'draft' | 'published' | undefined>();

  const isContributor = user?.role === 'contributor';
  const canPublish = !isContributor;

  const { data, isLoading } = useQuery({
    queryKey: ['content', type, status],
    queryFn: () => content.list({ type, status }),
  });

  const deleteMutation = useMutation({
    mutationFn: content.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['content'] });
    },
  });

  const publishMutation = useMutation({
    mutationFn: content.publish,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['content'] });
    },
  });

  const unpublishMutation = useMutation({
    mutationFn: content.unpublish,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['content'] });
    },
  });

  const title = type === 'page' ? 'Pages' : 'Posts';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">{title}</h1>
        <Link to={`/content/new?type=${type}`} className="btn btn-primary btn-sm">
          <Plus className="w-4 h-4 mr-1" /> New {type === 'page' ? 'Page' : 'Post'}
        </Link>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        <button
          onClick={() => setStatus(undefined)}
          className={`btn btn-sm ${!status ? 'btn-primary' : 'btn-secondary'}`}
        >
          All
        </button>
        <button
          onClick={() => setStatus('published')}
          className={`btn btn-sm ${status === 'published' ? 'btn-primary' : 'btn-secondary'}`}
        >
          Published
        </button>
        <button
          onClick={() => setStatus('draft')}
          className={`btn btn-sm ${status === 'draft' ? 'btn-primary' : 'btn-secondary'}`}
        >
          Drafts
        </button>
      </div>

      {/* Content list */}
      <div className="card">
        {isLoading ? (
          <div className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : data?.items.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-gray-500">No {title.toLowerCase()} found</p>
            <Link
              to={`/content/new?type=${type}`}
              className="text-primary hover:underline text-sm mt-2 inline-block"
            >
              Create your first {type}
            </Link>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">
                  Title
                </th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">
                  Slug
                </th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">
                  Status
                </th>
                <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">
                  Last Edited
                </th>
                <th className="text-right py-3 px-4 text-sm font-medium text-gray-500">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {data?.items.map((item) => (
                <tr key={item.id} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-3 px-4">
                    <Link
                      to={`/content/${item.id}`}
                      className="text-sm font-medium text-gray-900 hover:text-primary"
                    >
                      {item.title}
                    </Link>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-sm text-gray-500">/{item.slug}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`text-xs px-2 py-1 rounded ${
                        item.status === 'published'
                          ? 'bg-green-100 text-green-700'
                          : 'bg-yellow-100 text-yellow-700'
                      }`}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="text-sm text-gray-500">
                      {new Date(item.updatedAt).toLocaleDateString()}
                    </div>
                    {item.author && (
                      <div className="text-xs text-gray-400">
                        by {item.author.name || item.author.email}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex justify-end gap-1">
                      {/* Contributors can only edit drafts */}
                      {(!isContributor || item.status === 'draft') && (
                        <Link
                          to={`/content/${item.id}`}
                          className="p-2 text-gray-400 hover:text-gray-600"
                          title="Edit"
                        >
                          <Pencil className="w-4 h-4" />
                        </Link>
                      )}
                      {/* Only editors and admins can publish/unpublish */}
                      {canPublish && (
                        item.status === 'draft' ? (
                          <button
                            onClick={() => publishMutation.mutate(item.id)}
                            className="p-2 text-gray-400 hover:text-green-600"
                            title="Publish"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        ) : (
                          <button
                            onClick={() => unpublishMutation.mutate(item.id)}
                            className="p-2 text-gray-400 hover:text-yellow-600"
                            title="Unpublish"
                          >
                            <EyeOff className="w-4 h-4" />
                          </button>
                        )
                      )}
                      {/* Only editors and admins can delete */}
                      {canPublish && (
                        <button
                          onClick={() => {
                            if (confirm('Are you sure you want to delete this?')) {
                              deleteMutation.mutate(item.id);
                            }
                          }}
                          className="p-2 text-gray-400 hover:text-red-600"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination info */}
      {data && data.pagination.total > 0 && (
        <p className="text-sm text-gray-500 text-center">
          Showing {data.items.length} of {data.pagination.total} {title.toLowerCase()}
        </p>
      )}
    </div>
  );
}
