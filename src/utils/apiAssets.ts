import { API_BASE_URL } from '@/utils/apiBase';
import { useAuthStore } from '@/store/authStore';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** Bearer header for the JWT issued by /api/auth; empty for guests. */
export function authHeaders(): Record<string, string> {
  const token = useAuthStore.getState().token;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function normalizeAsset(raw: any) {
  const priceAmount = Number(raw?.price?.amount ?? raw?.value ?? 0);
  return {
    ...raw,
    imageUrl: raw?.imageUrl || raw?.images?.[0] || '',
    value: Number.isFinite(Number(raw?.value)) ? Number(raw.value) : priceAmount,
    views: raw?.views ?? 0,
    likes: raw?.likes ?? 0,
    tokenId: raw?.tokenId || raw?.id || '',
    createdAt: raw?.createdAt ? new Date(raw.createdAt) : new Date(),
    updatedAt: raw?.updatedAt ? new Date(raw.updatedAt) : new Date(),
    price: {
      amount: Number.isFinite(priceAmount) ? priceAmount : 0,
      currency: raw?.price?.currency || 'USDT',
    },
  };
}

export async function fetchAssetsFromApi(params?: Record<string, string | number | undefined>) {
  const query = new URLSearchParams();
  query.set('limit', String(params?.limit ?? 100));
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && key !== 'limit') {
      query.set(key, String(value));
    }
  });
  const response = await fetch(`${API_BASE_URL}/assets?${query.toString()}`);
  if (!response.ok) {
    throw new Error('Failed to fetch assets');
  }
  const data = await response.json();
  const assets = Array.isArray(data?.assets) ? data.assets : Array.isArray(data) ? data : [];
  return assets.map(normalizeAsset);
}

export async function fetchAssetByIdFromApi(id: string) {
  const response = await fetch(`${API_BASE_URL}/assets/${encodeURIComponent(id)}`);
  if (!response.ok) {
    throw new Error('Failed to fetch asset');
  }
  return normalizeAsset(await response.json());
}

export async function createAssetOnApi(asset: any) {
  const description = String(asset.description || '');
  const payload = {
    title: asset.title,
    description: description.length >= 10 ? description : `${description} tokenized asset`.trim(),
    category: asset.category || 'other',
    price: asset.price,
    tokenization: asset.tokenization,
    listingType: asset.listingType || 'fixed',
    imageUrl: typeof asset.imageUrl === 'string' && asset.imageUrl.startsWith('http')
      ? asset.imageUrl
      : 'https://images.pexels.com/photos/9978722/pexels-photo-9978722.jpeg',
    images: Array.isArray(asset.images) ? asset.images.filter((url: string) => typeof url === 'string' && url.startsWith('http')) : [],
    // owner/status/isVerified are decided by the server from the JWT, not sent by the client.
    tokenId: asset.tokenId,
    value: asset.value ?? asset.price?.amount,
  };

  const response = await fetch(`${API_BASE_URL}/assets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new ApiError(response.status, data?.error || 'Failed to create asset');
  }
  return normalizeAsset(await response.json());
}
