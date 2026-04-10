import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { categories, Category } from '../lib/api';
import { Plus, Pencil, Trash2, X, Check } from 'lucide-react';

export default function Categories() {
  const queryClient = useQueryClient();
  const [editingId, setEditingId] = useState<string | null>(null);
  const [newCategory, setNewCategory] = useState<{ name: string; parentId?: string } | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['categories'],
    queryFn: categories.list,
  });

  const createMutation = useMutation({
    mutationFn: categories.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['categories'] });
      setNewCategory(null);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { name?: string; slug?: string } }) =>
      categories.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['categories'] });
      setEditingId(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: categories.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['categories'] });
    },
  });

  const renderCategory = (category: Category, level = 0) => {
    const isEditing = editingId === category.id;

    return (
      <div key={category.id}>
        <div
          className={`flex items-center justify-between py-3 px-4 hover:bg-gray-50 ${
            level > 0 ? 'border-l-2 border-gray-200 ml-6' : ''
          }`}
        >
          {isEditing ? (
            <EditCategoryForm
              category={category}
              onSave={(name) => {
                updateMutation.mutate({ id: category.id, data: { name } });
              }}
              onCancel={() => setEditingId(null)}
            />
          ) : (
            <>
              <div>
                <span className="font-medium text-gray-900">{category.name}</span>
                <span className="text-sm text-gray-500 ml-2">/{category.slug}</span>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setNewCategory({ name: '', parentId: category.id })}
                  className="p-2 text-gray-400 hover:text-gray-600"
                  title="Add child"
                >
                  <Plus className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setEditingId(category.id)}
                  className="p-2 text-gray-400 hover:text-gray-600"
                  title="Edit"
                >
                  <Pencil className="w-4 h-4" />
                </button>
                <button
                  onClick={() => {
                    if (confirm('Delete this category?')) {
                      deleteMutation.mutate(category.id);
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

        {/* Show add form under this category if adding child */}
        {newCategory?.parentId === category.id && (
          <div className="ml-6 border-l-2 border-gray-200">
            <div className="py-3 px-4 bg-gray-50">
              <NewCategoryForm
                parentId={category.id}
                onSave={(name) => {
                  createMutation.mutate({ name, parentId: category.id });
                }}
                onCancel={() => setNewCategory(null)}
              />
            </div>
          </div>
        )}

        {/* Render children */}
        {category.children?.map((child) => renderCategory(child, level + 1))}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Categories</h1>
        <button
          onClick={() => setNewCategory({ name: '' })}
          className="btn btn-primary btn-sm"
        >
          <Plus className="w-4 h-4 mr-1" /> New Category
        </button>
      </div>

      <div className="card">
        {isLoading ? (
          <div className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : data?.items.length === 0 && !newCategory ? (
          <div className="text-center py-8">
            <p className="text-gray-500">No categories yet</p>
            <button
              onClick={() => setNewCategory({ name: '' })}
              className="text-primary hover:underline text-sm mt-2"
            >
              Create your first category
            </button>
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {/* New root category form */}
            {newCategory && !newCategory.parentId && (
              <div className="py-3 px-4 bg-gray-50">
                <NewCategoryForm
                  onSave={(name) => {
                    createMutation.mutate({ name });
                  }}
                  onCancel={() => setNewCategory(null)}
                />
              </div>
            )}

            {data?.items.map((category) => renderCategory(category))}
          </div>
        )}
      </div>
    </div>
  );
}

function NewCategoryForm({
  parentId,
  onSave,
  onCancel,
}: {
  parentId?: string;
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
        placeholder={parentId ? 'Child category name...' : 'Category name...'}
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

function EditCategoryForm({
  category,
  onSave,
  onCancel,
}: {
  category: Category;
  onSave: (name: string) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(category.name);

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
