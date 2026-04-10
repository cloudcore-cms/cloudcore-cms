import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { tags, Tag } from '../lib/api';
import { Plus, Pencil, Trash2, X, Check } from 'lucide-react';

export default function Tags() {
  const queryClient = useQueryClient();
  const [editingId, setEditingId] = useState<string | null>(null);
  const [showNewForm, setShowNewForm] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ['tags'],
    queryFn: tags.list,
  });

  const createMutation = useMutation({
    mutationFn: tags.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tags'] });
      setShowNewForm(false);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { name?: string } }) =>
      tags.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tags'] });
      setEditingId(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: tags.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tags'] });
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Tags</h1>
        <button
          onClick={() => setShowNewForm(true)}
          className="btn btn-primary btn-sm"
        >
          <Plus className="w-4 h-4 mr-1" /> New Tag
        </button>
      </div>

      <div className="card">
        {isLoading ? (
          <div className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : data?.items.length === 0 && !showNewForm ? (
          <div className="text-center py-8">
            <p className="text-gray-500">No tags yet</p>
            <button
              onClick={() => setShowNewForm(true)}
              className="text-primary hover:underline text-sm mt-2"
            >
              Create your first tag
            </button>
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {/* New tag form */}
            {showNewForm && (
              <div className="py-3 px-4 bg-gray-50">
                <NewTagForm
                  onSave={(name) => {
                    createMutation.mutate({ name });
                  }}
                  onCancel={() => setShowNewForm(false)}
                />
              </div>
            )}

            {data?.items.map((tag) => {
              const isEditing = editingId === tag.id;

              return (
                <div
                  key={tag.id}
                  className="flex items-center justify-between py-3 px-4 hover:bg-gray-50"
                >
                  {isEditing ? (
                    <EditTagForm
                      tag={tag}
                      onSave={(name) => {
                        updateMutation.mutate({ id: tag.id, data: { name } });
                      }}
                      onCancel={() => setEditingId(null)}
                    />
                  ) : (
                    <>
                      <div>
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-gray-100 text-gray-800">
                          {tag.name}
                        </span>
                        <span className="text-sm text-gray-500 ml-2">/{tag.slug}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => setEditingId(tag.id)}
                          className="p-2 text-gray-400 hover:text-gray-600"
                          title="Edit"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => {
                            if (confirm('Delete this tag?')) {
                              deleteMutation.mutate(tag.id);
                            }
                          }}
                          className="p-2 text-gray-400 hover:text-red-600"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function NewTagForm({
  onSave,
  onCancel,
}: {
  onSave: (name: string) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (name.trim()) {
      onSave(name.trim());
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex items-center gap-2">
      <input
        type="text"
        value={name}
        onChange={(e) => setName(e.target.value)}
        className="input flex-1"
        placeholder="Tag name..."
        autoFocus
      />
      <button type="submit" className="p-2 text-green-600 hover:text-green-700">
        <Check className="w-5 h-5" />
      </button>
      <button type="button" onClick={onCancel} className="p-2 text-gray-400 hover:text-gray-600">
        <X className="w-5 h-5" />
      </button>
    </form>
  );
}

function EditTagForm({
  tag,
  onSave,
  onCancel,
}: {
  tag: Tag;
  onSave: (name: string) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(tag.name);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (name.trim()) {
      onSave(name.trim());
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex items-center gap-2 flex-1">
      <input
        type="text"
        value={name}
        onChange={(e) => setName(e.target.value)}
        className="input flex-1"
        autoFocus
      />
      <button type="submit" className="p-2 text-green-600 hover:text-green-700">
        <Check className="w-5 h-5" />
      </button>
      <button type="button" onClick={onCancel} className="p-2 text-gray-400 hover:text-gray-600">
        <X className="w-5 h-5" />
      </button>
    </form>
  );
}
