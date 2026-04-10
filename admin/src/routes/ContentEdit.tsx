import { useState, useEffect } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { content, blocks, categories, tags, ContentBlock } from '../lib/api';
import { useAuth } from '../lib/auth';
import BlockEditor from '../components/BlockEditor';
import { Save, ArrowLeft, Eye, EyeOff, History, AlertTriangle } from 'lucide-react';

export default function ContentEdit() {
  const { id } = useParams();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();

  const isNew = !id;
  const defaultType = (searchParams.get('type') as 'page' | 'post') || 'page';
  const isContributor = user?.role === 'contributor';
  const canPublish = !isContributor;

  const [title, setTitle] = useState('');
  const [slug, setSlug] = useState('');
  const [type, setType] = useState<'page' | 'post'>(defaultType);
  const [status, setStatus] = useState<'draft' | 'published'>('draft');
  const [contentBlocks, setContentBlocks] = useState<ContentBlock[]>([]);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [showRevisions, setShowRevisions] = useState(false);

  // Fetch existing content
  const { data: existingContent, isLoading } = useQuery({
    queryKey: ['content', id],
    queryFn: () => content.get(id!),
    enabled: !isNew,
  });

  // Fetch block types
  const { data: blockTypes } = useQuery({
    queryKey: ['blocks'],
    queryFn: blocks.list,
  });

  // Fetch categories and tags
  const { data: categoriesData } = useQuery({
    queryKey: ['categories'],
    queryFn: categories.list,
  });

  const { data: tagsData } = useQuery({
    queryKey: ['tags'],
    queryFn: tags.list,
  });

  // Fetch revisions
  const { data: revisionsData } = useQuery({
    queryKey: ['revisions', id],
    queryFn: () => content.revisions(id!),
    enabled: !isNew && showRevisions,
  });

  // Load existing content
  useEffect(() => {
    if (existingContent) {
      setTitle(existingContent.title);
      setSlug(existingContent.slug);
      setType(existingContent.type);
      setStatus(existingContent.status);
      setContentBlocks(existingContent.blocks);
      setSelectedCategories(existingContent.categories?.map((c) => c.id) || []);
      setSelectedTags(existingContent.tags?.map((t) => t.id) || []);
    }
  }, [existingContent]);

  // Auto-generate slug from title
  useEffect(() => {
    if (isNew && title && !slug) {
      setSlug(
        title
          .toLowerCase()
          .replace(/[^a-z0-9\s-]/g, '')
          .replace(/\s+/g, '-')
          .replace(/-+/g, '-')
      );
    }
  }, [title, isNew, slug]);

  // Create mutation
  const createMutation = useMutation({
    mutationFn: () =>
      content.create({
        type,
        title,
        slug,
        status,
        blocks: contentBlocks,
        categoryIds: type === 'post' ? selectedCategories : undefined,
        tagIds: type === 'post' ? selectedTags : undefined,
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['content'] });
      navigate(`/content/${data.id}`);
    },
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: () =>
      content.update(id!, {
        title,
        slug,
        status,
        blocks: contentBlocks,
        categoryIds: type === 'post' ? selectedCategories : undefined,
        tagIds: type === 'post' ? selectedTags : undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['content'] });
    },
  });

  // Publish/unpublish mutations
  const publishMutation = useMutation({
    mutationFn: () => content.publish(id!),
    onSuccess: () => {
      setStatus('published');
      queryClient.invalidateQueries({ queryKey: ['content'] });
    },
  });

  const unpublishMutation = useMutation({
    mutationFn: () => content.unpublish(id!),
    onSuccess: () => {
      setStatus('draft');
      queryClient.invalidateQueries({ queryKey: ['content'] });
    },
  });

  // Restore revision mutation
  const restoreRevisionMutation = useMutation({
    mutationFn: (revisionId: string) => content.restoreRevision(id!, revisionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['content', id] });
      setShowRevisions(false);
    },
  });

  const handleSave = () => {
    if (isNew) {
      createMutation.mutate();
    } else {
      updateMutation.mutate();
    }
  };

  const isSaving = createMutation.isPending || updateMutation.isPending;

  if (!isNew && isLoading) {
    return (
      <div className="flex justify-center py-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  // Contributors cannot edit published content
  const isPublished = existingContent?.status === 'published';
  const contributorBlockedFromEditing = isContributor && isPublished && !isNew;

  if (contributorBlockedFromEditing) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate(type === 'page' ? '/pages' : '/posts')}
            className="p-2 text-gray-400 hover:text-gray-600"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <h1 className="text-2xl font-bold text-gray-900">View Content</h1>
        </div>
        <div className="card">
          <div className="flex items-start gap-3 p-4 bg-yellow-50 rounded-lg border border-yellow-200">
            <AlertTriangle className="w-5 h-5 text-yellow-600 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="font-medium text-yellow-800">Read-only access</h3>
              <p className="text-sm text-yellow-700 mt-1">
                As a contributor, you can only edit draft content. This content is published and can only be edited by editors or admins.
              </p>
            </div>
          </div>
          <div className="mt-6 space-y-4">
            <div>
              <label className="label">Title</label>
              <p className="text-gray-900 mt-1">{existingContent?.title}</p>
            </div>
            <div>
              <label className="label">Slug</label>
              <p className="text-gray-500 mt-1">/{existingContent?.slug}</p>
            </div>
            <div>
              <label className="label">Status</label>
              <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-700 mt-1">
                Published
              </span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate(type === 'page' ? '/pages' : '/posts')}
            className="p-2 text-gray-400 hover:text-gray-600"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <h1 className="text-2xl font-bold text-gray-900">
            {isNew ? `New ${type === 'page' ? 'Page' : 'Post'}` : 'Edit Content'}
          </h1>
        </div>
        <div className="flex items-center gap-2">
          {!isNew && (
            <>
              <button
                onClick={() => setShowRevisions(!showRevisions)}
                className="btn btn-secondary btn-sm"
              >
                <History className="w-4 h-4 mr-1" /> Revisions
              </button>
              {/* Only editors and admins can publish/unpublish */}
              {canPublish && (
                status === 'draft' ? (
                  <button
                    onClick={() => publishMutation.mutate()}
                    className="btn btn-secondary btn-sm"
                    disabled={publishMutation.isPending}
                  >
                    <Eye className="w-4 h-4 mr-1" /> Publish
                  </button>
                ) : (
                  <button
                    onClick={() => unpublishMutation.mutate()}
                    className="btn btn-secondary btn-sm"
                    disabled={unpublishMutation.isPending}
                  >
                    <EyeOff className="w-4 h-4 mr-1" /> Unpublish
                  </button>
                )
              )}
            </>
          )}
          <button
            onClick={handleSave}
            className="btn btn-primary btn-sm"
            disabled={isSaving || !title}
          >
            <Save className="w-4 h-4 mr-1" /> {isSaving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Main content area */}
        <div className="lg:col-span-3 space-y-6">
          {/* Title */}
          <div className="card">
            <div className="space-y-4">
              <div>
                <label className="label">Title</label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="input mt-1"
                  placeholder="Enter title..."
                />
              </div>
              <div>
                <label className="label">Slug</label>
                <div className="flex items-center mt-1">
                  <span className="text-gray-500 text-sm mr-1">/</span>
                  <input
                    type="text"
                    value={slug}
                    onChange={(e) =>
                      setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))
                    }
                    className="input"
                    placeholder="url-slug"
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Block Editor */}
          <div className="card">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Content</h2>
            <BlockEditor
              blocks={contentBlocks}
              onChange={setContentBlocks}
              blockTypes={blockTypes?.items || []}
            />
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Status */}
          <div className="card">
            <h3 className="text-sm font-medium text-gray-900 mb-3">Status</h3>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as 'draft' | 'published')}
              className="input"
              disabled={isContributor}
            >
              <option value="draft">Draft</option>
              {canPublish && <option value="published">Published</option>}
            </select>
            {isContributor && (
              <p className="text-xs text-gray-500 mt-2">
                Contributors can only save drafts. An editor or admin must publish your content.
              </p>
            )}
          </div>

          {/* Type (only for new) */}
          {isNew && (
            <div className="card">
              <h3 className="text-sm font-medium text-gray-900 mb-3">Type</h3>
              <select
                value={type}
                onChange={(e) => setType(e.target.value as 'page' | 'post')}
                className="input"
              >
                <option value="page">Page</option>
                <option value="post">Post</option>
              </select>
            </div>
          )}

          {/* Categories (posts only) */}
          {type === 'post' && (
            <div className="card">
              <h3 className="text-sm font-medium text-gray-900 mb-3">Categories</h3>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {categoriesData?.items.map((cat) => (
                  <label key={cat.id} className="flex items-center">
                    <input
                      type="checkbox"
                      checked={selectedCategories.includes(cat.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedCategories([...selectedCategories, cat.id]);
                        } else {
                          setSelectedCategories(
                            selectedCategories.filter((id) => id !== cat.id)
                          );
                        }
                      }}
                      className="rounded border-gray-300 text-primary focus:ring-primary"
                    />
                    <span className="ml-2 text-sm text-gray-700">{cat.name}</span>
                  </label>
                ))}
                {categoriesData?.items.length === 0 && (
                  <p className="text-sm text-gray-500">No categories yet</p>
                )}
              </div>
            </div>
          )}

          {/* Tags (posts only) */}
          {type === 'post' && (
            <div className="card">
              <h3 className="text-sm font-medium text-gray-900 mb-3">Tags</h3>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {tagsData?.items.map((tag) => (
                  <label key={tag.id} className="flex items-center">
                    <input
                      type="checkbox"
                      checked={selectedTags.includes(tag.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedTags([...selectedTags, tag.id]);
                        } else {
                          setSelectedTags(selectedTags.filter((id) => id !== tag.id));
                        }
                      }}
                      className="rounded border-gray-300 text-primary focus:ring-primary"
                    />
                    <span className="ml-2 text-sm text-gray-700">{tag.name}</span>
                  </label>
                ))}
                {tagsData?.items.length === 0 && (
                  <p className="text-sm text-gray-500">No tags yet</p>
                )}
              </div>
            </div>
          )}

          {/* Revisions panel */}
          {showRevisions && revisionsData && (
            <div className="card">
              <h3 className="text-sm font-medium text-gray-900 mb-3">Revisions</h3>
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {revisionsData.items.length === 0 ? (
                  <p className="text-sm text-gray-500">No revisions yet</p>
                ) : (
                  revisionsData.items.map((rev) => (
                    <div
                      key={rev.id}
                      className="flex items-center justify-between py-2 border-b border-gray-100 last:border-0"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-medium text-gray-900 truncate">{rev.title}</p>
                          {rev.changeType && (
                            <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${
                              rev.changeType === 'create' ? 'bg-green-100 text-green-700' :
                              rev.changeType === 'publish' ? 'bg-blue-100 text-blue-700' :
                              rev.changeType === 'unpublish' ? 'bg-yellow-100 text-yellow-700' :
                              rev.changeType === 'restore' ? 'bg-purple-100 text-purple-700' :
                              'bg-gray-100 text-gray-700'
                            }`}>
                              {rev.changeType}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-gray-500">
                          {new Date(rev.createdAt).toLocaleString()}
                          {(rev.authorName || rev.authorEmail) && (
                            <span className="ml-1">
                              by <span className="font-medium">{rev.authorName || rev.authorEmail}</span>
                            </span>
                          )}
                        </p>
                      </div>
                      <button
                        onClick={() => {
                          if (confirm('Restore this revision?')) {
                            restoreRevisionMutation.mutate(rev.id);
                          }
                        }}
                        className="text-xs text-primary hover:underline ml-2 flex-shrink-0"
                      >
                        Restore
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
