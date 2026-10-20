import { get, set } from 'idb-keyval';
export const getIdentities = async () => await get('sfs-identities') || [];
export async function saveIdentity(id) {
  const ids = await getIdentities();
  await set('sfs-identities', [...ids.filter(i => i.userId !== id.userId), id]);
}
export const cacheEnabled = async () => (await get('sfs-cache-enabled')) !== false;
export const setCacheEnabled = enabled => set('sfs-cache-enabled', enabled);
export async function cacheKey(id, g, keys) {
  if (await cacheEnabled()) await set(`sfs-key:${id.userId}:${g}:${keys.version}`, keys);
}
export const cachedKey = (id, g, v) => get(`sfs-key:${id.userId}:${g}:${v}`);
