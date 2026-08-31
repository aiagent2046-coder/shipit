// The one line this whole stand exists to demonstrate.
//
// A browser Supabase client, constructed with whatever key VITE_SUPABASE_KEY
// holds. In a real vibe-coded app this is written as
//
//     createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY)
//
// — the developer prefixed the service-role key with VITE_ to make it "work",
// not knowing the prefix is precisely what inlines it into the shipped bundle.
// Here the variant is chosen by the VALUE bound to VITE_SUPABASE_KEY at build
// time (see build_variants.sh): the service-role JWT for the vulnerable build,
// the anon JWT for the patched one. The source is identical; only the key
// baked in differs, which is the real before/after of this fix.
import { createClient } from '@supabase/supabase-js'

const url = import.meta.env.VITE_SUPABASE_URL as string
const key = import.meta.env.VITE_SUPABASE_KEY as string

const supabase = createClient(url, key)

// A real read, so a tree-shaker cannot drop the key as dead code — the leak has
// to survive a production build to be worth proving.
supabase
  .from('founders')
  .select('*')
  .limit(3)
  .then(({ data, error }) => {
    const el = document.getElementById('app')
    if (el) el.textContent = error ? String(error.message) : JSON.stringify(data)
  })
