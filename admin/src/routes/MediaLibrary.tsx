import { useState, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { media, Media } from '../lib/api';
import { Upload, Trash2, Copy, Check, X } from 'lucide-react';

export default function MediaLibrary() {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedMedia, setSelectedMedia] = useState<Media | null>(null);
  const [uploading, setUploading] = useState(false);
  const [copied, setCopied] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ['media'],
    queryFn: () => media.list({ limit: 50 }),
  });

  const uploadMutation = useMutation({
    mutationFn: media.upload,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['media'] });
      setUploading(false);
    },
    onError: () => {
      setUploading(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: media.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['media'] });
      setSelectedMedia(null);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, alt }: { id: string; alt: string }) =>
      media.update(id, { alt }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['media'] });
    },
  });

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setUploading(true);
    for (const file of Array.from(files)) {
      await uploadMutation.mutateAsync(file);
    }
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;

    setUploading(true);
    for (const file of Array.from(files)) {
      await uploadMutation.mutateAsync(file);
    }
  };

  const copyUrl = (mediaItem: Media) => {
    navigator.clipboard.writeText(mediaItem.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const formatFileSize = (bytes: number | null) => {
    if (!bytes) return 'Unknown';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Media Library</h1>
        <button
          onClick={() => fileInputRef.current?.click()}
          className="btn btn-primary btn-sm"
          disabled={uploading}
        >
          <Upload className="w-4 h-4 mr-1" />
          {uploading ? 'Uploading...' : 'Upload'}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept="image/*,video/*,audio/*,application/pdf"
          onChange={handleFileSelect}
          className="hidden"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Media grid */}
        <div className="lg:col-span-2">
          <div
            className="card min-h-[400px]"
            onDrop={handleDrop}
            onDragOver={(e) => e.preventDefault()}
          >
            {isLoading ? (
              <div className="flex justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              </div>
            ) : data?.items.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <Upload className="w-12 h-12 text-gray-300 mb-4" />
                <p className="text-gray-500 mb-2">No media files yet</p>
                <p className="text-sm text-gray-400">
                  Drag and drop files here or click Upload
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 gap-4">
                {data?.items.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setSelectedMedia(item)}
                    className={`relative aspect-square rounded-lg overflow-hidden border-2 transition-colors ${
                      selectedMedia?.id === item.id
                        ? 'border-primary'
                        : 'border-transparent hover:border-gray-300'
                    }`}
                  >
                    {item.mimeType.startsWith('image/') ? (
                      <img
                        src={item.url}
                        alt={item.alt || item.filename}
                        className="w-full h-full object-cover"
                      />
                    ) : (
                      <div className="w-full h-full bg-gray-100 flex items-center justify-center">
                        <span className="text-xs text-gray-500 text-center px-2 truncate">
                          {item.filename}
                        </span>
                      </div>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Selected media details */}
        <div className="lg:col-span-1">
          {selectedMedia ? (
            <div className="card space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="font-medium text-gray-900">Details</h3>
                <button
                  onClick={() => setSelectedMedia(null)}
                  className="p-1 text-gray-400 hover:text-gray-600"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Preview */}
              {selectedMedia.mimeType.startsWith('image/') && (
                <img
                  src={selectedMedia.url}
                  alt={selectedMedia.alt || selectedMedia.filename}
                  className="w-full rounded-lg"
                />
              )}

              {/* Info */}
              <div className="space-y-2 text-sm">
                <div>
                  <span className="text-gray-500">Filename:</span>
                  <span className="ml-2 text-gray-900">{selectedMedia.filename}</span>
                </div>
                <div>
                  <span className="text-gray-500">Type:</span>
                  <span className="ml-2 text-gray-900">{selectedMedia.mimeType}</span>
                </div>
                <div>
                  <span className="text-gray-500">Size:</span>
                  <span className="ml-2 text-gray-900">
                    {formatFileSize(selectedMedia.size)}
                  </span>
                </div>
                {selectedMedia.width && selectedMedia.height && (
                  <div>
                    <span className="text-gray-500">Dimensions:</span>
                    <span className="ml-2 text-gray-900">
                      {selectedMedia.width} x {selectedMedia.height}
                    </span>
                  </div>
                )}
                <div>
                  <span className="text-gray-500">ID:</span>
                  <span className="ml-2 text-gray-900 font-mono text-xs">
                    {selectedMedia.id}
                  </span>
                </div>
                <div>
                  <span className="text-gray-500">Uploaded:</span>
                  <span className="ml-2 text-gray-900">
                    {new Date(selectedMedia.createdAt).toLocaleDateString()}
                  </span>
                </div>
                {selectedMedia.uploadedBy && (
                  <div>
                    <span className="text-gray-500">By:</span>
                    <span className="ml-2 text-gray-900">
                      {selectedMedia.uploadedBy.name || selectedMedia.uploadedBy.email}
                    </span>
                  </div>
                )}
              </div>

              {/* Alt text */}
              <div>
                <label className="label">Alt Text</label>
                <input
                  type="text"
                  value={selectedMedia.alt || ''}
                  onChange={(e) => {
                    setSelectedMedia({ ...selectedMedia, alt: e.target.value });
                  }}
                  onBlur={() => {
                    updateMutation.mutate({
                      id: selectedMedia.id,
                      alt: selectedMedia.alt || '',
                    });
                  }}
                  className="input mt-1"
                  placeholder="Describe the image..."
                />
              </div>

              {/* Actions */}
              <div className="flex gap-2">
                <button
                  onClick={() => copyUrl(selectedMedia)}
                  className="btn btn-secondary btn-sm flex-1"
                >
                  {copied ? (
                    <>
                      <Check className="w-4 h-4 mr-1" /> Copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4 mr-1" /> Copy URL
                    </>
                  )}
                </button>
                <button
                  onClick={() => {
                    if (confirm('Delete this media file?')) {
                      deleteMutation.mutate(selectedMedia.id);
                    }
                  }}
                  className="btn btn-destructive btn-sm"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ) : (
            <div className="card text-center py-8">
              <p className="text-gray-500">Select a file to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
