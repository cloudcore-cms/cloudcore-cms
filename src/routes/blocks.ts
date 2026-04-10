import { Hono } from 'hono';
import type { Env, Variables } from '../types';
import { BLOCK_TYPES, getBlockTypeList } from '../blocks/types';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Get all block types (for admin UI)
app.get('/', async (c) => {
  return c.json({
    items: getBlockTypeList(),
  });
});

// Get single block type definition
app.get('/:type', async (c) => {
  const type = c.req.param('type') as keyof typeof BLOCK_TYPES;

  if (!(type in BLOCK_TYPES)) {
    return c.json({ error: 'Block type not found' }, 404);
  }

  return c.json({
    type,
    ...BLOCK_TYPES[type],
  });
});

export default app;
