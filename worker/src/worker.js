export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method === 'POST' && url.pathname === '/signup') {
      try {
        const body = await request.json();
        const { email, name, neighborhood, building } = body;

        if (!email || !email.includes('@')) {
          return new Response(JSON.stringify({ success: false, error: 'Valid email required' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        await env.DB.prepare(
          'INSERT INTO signups (email, name, neighborhood, building) VALUES (?, ?, ?, ?)'
        ).bind(email, name || null, neighborhood || null, building || null).run();

        return new Response(JSON.stringify({ success: true, message: 'Welcome to the porch.' }), {
          status: 200,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });

      } catch (err) {
        if (err.message && err.message.includes('UNIQUE')) {
          return new Response(JSON.stringify({ success: false, error: 'Already on the list.' }), {
            status: 409,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
        return new Response(JSON.stringify({ success: false, error: 'Something went wrong.' }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response('Front Porch Economics API', { status: 200 });
  },
};
