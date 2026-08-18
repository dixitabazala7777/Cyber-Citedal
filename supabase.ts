import { createClient, SupabaseClient } from '@supabase/supabase-js';

const supabaseUrl = (import.meta as any).env?.VITE_SUPABASE_URL;
const supabaseAnonKey = (import.meta as any).env?.VITE_SUPABASE_ANON_KEY;


export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

let supabaseClient: SupabaseClient | null = null;

export function getSupabase() {
  if (!isSupabaseConfigured) {
    return null;
  }
  if (!supabaseClient) {
    try {
      supabaseClient = createClient(supabaseUrl!, supabaseAnonKey!);
    } catch (e) {
      console.error('[ShieldPulse] Failed to initialize Supabase client:', e);
    }
  }
  return supabaseClient;
}
