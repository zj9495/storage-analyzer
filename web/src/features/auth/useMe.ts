import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { MeResponse } from '../../api/types'

export function useMe() {
  return useQuery({
    queryKey: ['auth', 'me'],
    queryFn: async ({ signal }) =>
      (await api.get<MeResponse>('/api/v1/auth/me', { signal })).data,
    retry: false,
    staleTime: 60_000,
  })
}
