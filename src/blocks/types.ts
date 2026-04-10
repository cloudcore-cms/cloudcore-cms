// Block type definitions - hardcoded in code
// Frontend will match these types for rendering

export const BLOCK_TYPES = {
  // Text blocks
  paragraph: {
    label: 'Paragraph',
    input: 'textarea',
    description: 'A simple text paragraph',
  },
  heading: {
    label: 'Heading',
    input: 'text',
    options: {
      level: { type: 'select', values: [1, 2, 3, 4, 5, 6], default: 2 },
    },
    description: 'Section heading (h1-h6)',
  },
  quote: {
    label: 'Quote',
    input: 'textarea',
    options: {
      citation: { type: 'text', label: 'Citation' },
    },
    description: 'Blockquote with optional citation',
  },

  // Rich content
  richtext: {
    label: 'Rich Text',
    input: 'richtext',
    description: 'Rich text with formatting (bold, italic, links, lists)',
  },

  // Media blocks
  image: {
    label: 'Image',
    input: 'media',
    options: {
      caption: { type: 'text', label: 'Caption' },
      size: { type: 'select', values: ['small', 'medium', 'large', 'full'], default: 'large' },
    },
    description: 'Single image with caption',
  },
  gallery: {
    label: 'Gallery',
    input: 'media-multi',
    options: {
      columns: { type: 'select', values: [2, 3, 4], default: 3 },
    },
    description: 'Image gallery grid',
  },
  video: {
    label: 'Video',
    input: 'url',
    options: {
      autoplay: { type: 'checkbox', label: 'Autoplay', default: false },
    },
    description: 'YouTube, Vimeo, or direct video URL',
  },

  // Layout blocks
  button: {
    label: 'Button',
    input: 'text',
    options: {
      url: { type: 'url', label: 'Link URL' },
      style: { type: 'select', values: ['primary', 'secondary', 'outline'], default: 'primary' },
      openInNewTab: { type: 'checkbox', label: 'Open in new tab', default: false },
    },
    description: 'Call-to-action button',
  },
  spacer: {
    label: 'Spacer',
    input: 'none',
    options: {
      size: { type: 'select', values: ['sm', 'md', 'lg', 'xl'], default: 'md' },
    },
    description: 'Vertical spacing between blocks',
  },
  divider: {
    label: 'Divider',
    input: 'none',
    description: 'Horizontal line separator',
  },

  // Custom/raw
  html: {
    label: 'Custom HTML',
    input: 'code',
    description: 'Raw HTML content (use with caution)',
  },
  code: {
    label: 'Code Block',
    input: 'code',
    options: {
      language: { type: 'text', label: 'Language', default: 'javascript' },
    },
    description: 'Syntax highlighted code block',
  },

  // Embeds
  embed: {
    label: 'Embed',
    input: 'url',
    description: 'Embed external content (Twitter, Instagram, etc.)',
  },
} as const;

export type BlockType = keyof typeof BLOCK_TYPES;

// Get list of block types for the admin UI
export function getBlockTypeList() {
  return Object.entries(BLOCK_TYPES).map(([key, config]) => ({
    type: key,
    ...config,
  }));
}
