import type { StoreData } from './types';

export interface StorageReadWrite {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
}
export interface Storage extends StorageReadWrite {
  transaction<T>(callback: (tx: StorageReadWrite) => Promise<T>): Promise<T>;
}
interface Manifest { chunks: number }
const isManifest = (value: StoreData | Manifest): value is Manifest => 'chunks' in value;
const CHUNK_SIZE = 16000; // At most 64 KiB UTF-8 per value (also safe for legacy DO KV limits).
export async function loadState(storage: Storage): Promise<StoreData | undefined> {
  const value = await storage.get<StoreData | Manifest>('state');
  if (!value || !isManifest(value)) return value;
  const chunks: string[] = [];
  for (let i = 0; i < value.chunks; i++) {
    const chunk = await storage.get<string>(`state:${i}`);
    if (chunk === undefined) throw new Error('持久化状态不完整');
    chunks.push(chunk);
  }
  return JSON.parse(chunks.join('')) as StoreData;
}
export async function saveState(storage: Storage, data: StoreData): Promise<void> {
  const serialized = JSON.stringify(data);
  await storage.transaction(async tx => {
    const prior = await tx.get<StoreData | Manifest>('state');
    const oldCount = prior && isManifest(prior) ? prior.chunks : 0;
    let count = 0;
    if (serialized.length <= CHUNK_SIZE) {
      await tx.put('state', data);
    } else {
      count = Math.ceil(serialized.length / CHUNK_SIZE);
      for (let i = 0; i < count; i++) await tx.put(`state:${i}`, serialized.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE));
      await tx.put('state', { chunks: count });
    }
    for (let i = count; i < oldCount; i++) await tx.delete(`state:${i}`);
  });
}
