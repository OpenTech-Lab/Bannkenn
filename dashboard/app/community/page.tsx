'use client';

import { useCallback, useEffect, useState } from 'react';

interface CommunityIp {
  ip: string;
  source: string;
  sightings: number;
  last_seen_at: string;
}

const POLL_INTERVAL = 30_000;

export default function CommunityPage() {
  const [rows, setRows] = useState<CommunityIp[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchCommunityIps = useCallback(async () => {
    try {
      const res = await fetch('/api/community');
      if (!res.ok) {
        setError('Failed to fetch community IP list');
        return;
      }

      const data: CommunityIp[] = await res.json();
      setRows(data);
      setError(null);
      setLastUpdated(new Date());
    } catch {
      setError('Cannot reach server');
    }
  }, []);

  useEffect(() => {
    fetchCommunityIps();
    const id = setInterval(fetchCommunityIps, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [fetchCommunityIps]);

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Community IP Lists</h1>
          <p className="text-gray-400 text-sm mt-0.5">IPs ingested from community feeds</p>
        </div>
        {lastUpdated && (
          <span className="text-xs text-gray-500">Updated {lastUpdated.toLocaleTimeString()}</span>
        )}
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-300 px-4 py-3 rounded-lg text-sm">
          {error}
        </div>
      )}

      <div className="rounded-xl border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-900 border-b border-gray-800">
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-widest">IP</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-widest">Source</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-widest">Sightings</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-widest">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={4} className="text-center py-12 text-gray-600">
                  No community IPs yet
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr key={`${row.ip}-${row.source}`} className="border-b border-gray-800/50 hover:bg-gray-900/40 transition-colors">
                  <td className="px-4 py-3 font-mono text-gray-200">{row.ip}</td>
                  <td className="px-4 py-3 text-gray-400">{row.source}</td>
                  <td className="px-4 py-3 text-gray-300 tabular-nums">{row.sightings}</td>
                  <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                    {new Date(row.last_seen_at).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <p className="text-center text-xs text-gray-700">Auto-refreshes every {POLL_INTERVAL / 1000}s</p>
    </div>
  );
}
