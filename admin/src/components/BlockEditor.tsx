import { useState } from 'react';
import { ContentBlock, BlockType } from '../lib/api';
import { Plus, GripVertical, Trash2, ChevronDown } from 'lucide-react';
import RichTextEditor from './RichTextEditor';

interface BlockEditorProps {
  blocks: ContentBlock[];
  onChange: (blocks: ContentBlock[]) => void;
  blockTypes: BlockType[];
}

export default function BlockEditor({ blocks, onChange, blockTypes }: BlockEditorProps) {
  const [showAddMenu, setShowAddMenu] = useState(false);

  const addBlock = (type: string) => {
    const newBlock: ContentBlock = {
      id: `block-${Date.now()}`,
      type,
      value: '',
      options: {},
    };
    onChange([...blocks, newBlock]);
    setShowAddMenu(false);
  };

  const updateBlock = (index: number, updates: Partial<ContentBlock>) => {
    const newBlocks = [...blocks];
    newBlocks[index] = { ...newBlocks[index], ...updates };
    onChange(newBlocks);
  };

  const removeBlock = (index: number) => {
    onChange(blocks.filter((_, i) => i !== index));
  };

  const moveBlock = (from: number, to: number) => {
    if (to < 0 || to >= blocks.length) return;
    const newBlocks = [...blocks];
    const [moved] = newBlocks.splice(from, 1);
    newBlocks.splice(to, 0, moved);
    onChange(newBlocks);
  };

  const getBlockTypeConfig = (type: string) => {
    return blockTypes.find((bt) => bt.type === type);
  };

  return (
    <div className="space-y-4">
      {blocks.length === 0 && (
        <div className="text-center py-8 border-2 border-dashed border-gray-200 rounded-lg">
          <p className="text-gray-500 mb-4">No content blocks yet</p>
        </div>
      )}

      {blocks.map((block, index) => {
        const config = getBlockTypeConfig(block.type);
        return (
          <div
            key={block.id}
            className="border border-gray-200 rounded-lg bg-white"
          >
            {/* Block header */}
            <div className="flex items-center justify-between px-4 py-2 bg-gray-50 border-b border-gray-200 rounded-t-lg">
              <div className="flex items-center gap-2">
                <button
                  className="p-1 text-gray-400 hover:text-gray-600 cursor-grab"
                  onMouseDown={(e) => e.preventDefault()}
                >
                  <GripVertical className="w-4 h-4" />
                </button>
                <span className="text-sm font-medium text-gray-700">
                  {config?.label || block.type}
                </span>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => moveBlock(index, index - 1)}
                  disabled={index === 0}
                  className="p-1 text-gray-400 hover:text-gray-600 disabled:opacity-30"
                  title="Move up"
                >
                  <ChevronDown className="w-4 h-4 rotate-180" />
                </button>
                <button
                  onClick={() => moveBlock(index, index + 1)}
                  disabled={index === blocks.length - 1}
                  className="p-1 text-gray-400 hover:text-gray-600 disabled:opacity-30"
                  title="Move down"
                >
                  <ChevronDown className="w-4 h-4" />
                </button>
                <button
                  onClick={() => removeBlock(index)}
                  className="p-1 text-gray-400 hover:text-red-600"
                  title="Remove"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Block content */}
            <div className="p-4">
              <BlockInput
                block={block}
                config={config}
                onChange={(updates) => updateBlock(index, updates)}
              />
            </div>
          </div>
        );
      })}

      {/* Add block button */}
      <div className="relative">
        <button
          onClick={() => setShowAddMenu(!showAddMenu)}
          className="btn btn-secondary w-full"
        >
          <Plus className="w-4 h-4 mr-2" /> Add Block
        </button>

        {showAddMenu && (
          <div className="absolute left-0 right-0 mt-2 bg-white border border-gray-200 rounded-lg shadow-lg z-10 max-h-64 overflow-y-auto">
            {blockTypes.map((bt) => (
              <button
                key={bt.type}
                onClick={() => addBlock(bt.type)}
                className="w-full text-left px-4 py-2 hover:bg-gray-50 border-b border-gray-100 last:border-0"
              >
                <div className="font-medium text-sm text-gray-900">{bt.label}</div>
                {bt.description && (
                  <div className="text-xs text-gray-500">{bt.description}</div>
                )}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

interface BlockInputProps {
  block: ContentBlock;
  config?: BlockType;
  onChange: (updates: Partial<ContentBlock>) => void;
}

function BlockInput({ block, config, onChange }: BlockInputProps) {
  const inputType = config?.input || 'text';

  // Handle options if any
  const renderOptions = () => {
    if (!config?.options) return null;

    return (
      <div className="mt-3 pt-3 border-t border-gray-100 space-y-3">
        {Object.entries(config.options as Record<string, unknown>).map(([key, optConfig]) => {
          const opt = optConfig as { type: string; values?: unknown[]; label?: string; default?: unknown };
          const value = (block.options?.[key] as unknown) ?? opt.default ?? '';

          if (opt.type === 'select' && opt.values) {
            return (
              <div key={key}>
                <label className="label text-xs">{opt.label || key}</label>
                <select
                  value={String(value)}
                  onChange={(e) =>
                    onChange({
                      options: { ...block.options, [key]: e.target.value },
                    })
                  }
                  className="input mt-1"
                >
                  {(opt.values as (string | number)[]).map((v) => (
                    <option key={String(v)} value={String(v)}>
                      {String(v)}
                    </option>
                  ))}
                </select>
              </div>
            );
          }

          if (opt.type === 'checkbox') {
            return (
              <label key={key} className="flex items-center">
                <input
                  type="checkbox"
                  checked={Boolean(value)}
                  onChange={(e) =>
                    onChange({
                      options: { ...block.options, [key]: e.target.checked },
                    })
                  }
                  className="rounded border-gray-300"
                />
                <span className="ml-2 text-sm text-gray-700">
                  {opt.label || key}
                </span>
              </label>
            );
          }

          if (opt.type === 'text' || opt.type === 'url') {
            return (
              <div key={key}>
                <label className="label text-xs">{opt.label || key}</label>
                <input
                  type={opt.type === 'url' ? 'url' : 'text'}
                  value={String(value)}
                  onChange={(e) =>
                    onChange({
                      options: { ...block.options, [key]: e.target.value },
                    })
                  }
                  className="input mt-1"
                />
              </div>
            );
          }

          return null;
        })}
      </div>
    );
  };

  switch (inputType) {
    case 'textarea':
      return (
        <>
          <textarea
            value={block.value}
            onChange={(e) => onChange({ value: e.target.value })}
            className="textarea min-h-[120px]"
            placeholder="Enter text..."
          />
          {renderOptions()}
        </>
      );

    case 'richtext':
      return (
        <>
          <RichTextEditor
            value={block.value}
            onChange={(html) => onChange({ value: html })}
            placeholder="Start writing..."
          />
          {renderOptions()}
        </>
      );

    case 'code':
      return (
        <>
          <textarea
            value={block.value}
            onChange={(e) => onChange({ value: e.target.value })}
            className="textarea min-h-[160px] font-mono text-sm"
            placeholder="Enter code..."
          />
          {renderOptions()}
        </>
      );

    case 'url':
      return (
        <>
          <input
            type="url"
            value={block.value}
            onChange={(e) => onChange({ value: e.target.value })}
            className="input"
            placeholder="https://..."
          />
          {renderOptions()}
        </>
      );

    case 'media':
      return (
        <>
          <div className="border-2 border-dashed border-gray-200 rounded-lg p-4 text-center">
            {block.mediaId ? (
              <div className="space-y-2">
                <img
                  src={`/api/v1/media/${block.mediaId}/file`}
                  alt=""
                  className="max-h-48 mx-auto rounded"
                />
                <button
                  onClick={() => onChange({ mediaId: undefined })}
                  className="text-sm text-red-600 hover:underline"
                >
                  Remove
                </button>
              </div>
            ) : (
              <div>
                <input
                  type="text"
                  value={block.mediaId || ''}
                  onChange={(e) => onChange({ mediaId: e.target.value })}
                  className="input"
                  placeholder="Enter media ID..."
                />
                <p className="text-xs text-gray-500 mt-2">
                  Enter a media ID or upload via the Media Library
                </p>
              </div>
            )}
          </div>
          {renderOptions()}
        </>
      );

    case 'media-multi':
      return (
        <>
          <div className="border-2 border-dashed border-gray-200 rounded-lg p-4">
            <textarea
              value={block.mediaIds?.join('\n') || ''}
              onChange={(e) =>
                onChange({
                  mediaIds: e.target.value.split('\n').filter(Boolean),
                })
              }
              className="textarea"
              placeholder="Enter media IDs, one per line..."
            />
            <p className="text-xs text-gray-500 mt-2">
              Enter media IDs, one per line
            </p>
          </div>
          {renderOptions()}
        </>
      );

    case 'none':
      return <>{renderOptions()}</>;

    case 'text':
    default:
      return (
        <>
          <input
            type="text"
            value={block.value}
            onChange={(e) => onChange({ value: e.target.value })}
            className="input"
            placeholder="Enter text..."
          />
          {renderOptions()}
        </>
      );
  }
}
