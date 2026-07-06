import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { fetchFeed } from '@/lib/feed';

const FeedContext = createContext(null);

export function FeedProvider({ children }) {
  const [feed, setFeed] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchFeed();
      setFeed(data);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <FeedContext.Provider value={{ feed, loading, error, refetch: load }}>
      {children}
    </FeedContext.Provider>
  );
}

export function useFeed() {
  const ctx = useContext(FeedContext);
  if (!ctx) throw new Error('useFeed must be used within a FeedProvider');
  return ctx;
}
