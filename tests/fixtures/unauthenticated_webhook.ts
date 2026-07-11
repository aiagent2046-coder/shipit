// Supabase Edge Function callback — mirrors a real Lovable/Supabase
// pattern: an internal webhook callback with no signature or session
// token check before it mutates a database record.
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })

  const payload = await req.json()
  const { source_id, status, error } = payload
  // No token or signature verification before this mutation.
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  )
  await supabase.from('sources').update({ status, error }).eq('id', source_id)
  return new Response('ok', { headers: corsHeaders })
})
