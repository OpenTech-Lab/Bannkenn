'use client';

import { useParams, redirect } from 'next/navigation';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function BehaviorAgentRedirectPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();

  useEffect(() => {
    if (params?.id) {
      router.replace(`/agents/${params.id}`);
    }
  }, [params?.id, router]);

  return null;
}
