import { expect, it } from 'vitest';
import { loadState, saveState } from '../src/persistence';
import { MemoryStorage } from './support';
import type { StoreData } from '../src/types';

it('atomically chunks large snapshots, restores them, and removes stale chunks', async () => {
  const storage = new MemoryStorage();
  const data: StoreData = { drafts: {}, recent: [], hour: '', day: '', hourly: 0, daily: 0, audit: [] };
  data.drafts.a = { id: 'a', text: '\u5b57😀'.repeat(100000), hash: 'hash', expires: 0, state: 'pending', risk_flags: [] };
  await saveState(storage, data);
  expect(storage.values.size).toBeGreaterThan(2);
  for (const value of storage.values.values()) expect(new TextEncoder().encode(JSON.stringify(value)).length).toBeLessThan(128 * 1024);
  expect(await loadState(storage)).toEqual(data);
  const previous = structuredClone(data);
  const originalPut = storage.put.bind(storage);
  storage.put = async (key, value) => { if (key === 'state:1') throw new Error('simulated disk failure'); await originalPut(key, value); };
  data.daily = 2;
  await expect(saveState(storage, data)).rejects.toThrow('disk failure');
  expect(await loadState(storage)).toEqual(previous);
  storage.put = originalPut;
  data.drafts = {};
  await saveState(storage, data);
  expect(storage.values.size).toBe(1);
  expect(await loadState(storage)).toEqual(data);
});
