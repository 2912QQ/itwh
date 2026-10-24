import { connect } from 'cloudflare:sockets';
const enc = new TextEncoder();
const J = (d, s = 200, h = {}) =>
  new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', ...h } });
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const urlsafe = (s) => s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const eq = (a, b) => {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
};
const clip = (v, n) => String(v ?? '').trim().slice(0, n);

async function pbkdf2(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000 }, k, 256);
  return b64(bits);
}
async function sign(env, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return urlsafe(b64(await crypto.subtle.sign('HMAC', k, enc.encode(data))));
}
async function session(req, env) {
  const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)s=([^;]+)/);
  if (!m) return null;
  const [p, sig] = m[1].split('.');
  if (!p || !sig || !eq(await sign(env, p), sig)) return null;
  const [u, exp] = atob(p.replace(/-/g, '+').replace(/_/g, '/')).split('|');
  if (+exp < Date.now()) return null;
  const row = await env.DB.prepare('SELECT username, role FROM users WHERE username=?').bind(u).first();
  return row ? { u: row.username, role: row.role } : null;
}

// ---- 在线检测:对 地址:端口 做 TCP 连接探测 ----
const PORTS = { https: 443, http: 80, ssh: 22, telnet: 23, rdp: 3389 };
async function probe(d) {
  let host = d.address, port = +d.port || PORTS[d.protocol] || 443;
  if (/^https?:\/\//i.test(host)) {
    try {
      const u = new URL(host);
      host = u.hostname;
      port = +d.port || +u.port || (u.protocol === 'http:' ? 80 : 443);
    } catch { return { status: 0, latency: null }; }
  }
  const t0 = Date.now();
  let s;
  try {
    s = connect({ hostname: host, port });
    await Promise.race([s.opened, new Promise((_, r) => setTimeout(() => r(new Error('timeout')), 3000))]);
    return { status: 1, latency: Date.now() - t0 };
  } catch { return { status: 0, latency: null }; }
  finally { try { s && s.close().catch(() => {}); } catch {} }
}
async function check(env, d) {
  if (!d.monitor) return { status: null, latency: null, checked_at: null };
  const r = await probe(d), at = Date.now();
  await env.DB.prepare('UPDATE devices SET status=?, latency=?, checked_at=? WHERE id=?')
    .bind(r.status, r.latency, at, d.id).run();
  return { ...r, checked_at: at };
}
async function inBatches(list, fn, n = 6) {   // Workers 同时外连数有限,分批执行
  for (let i = 0; i < list.length; i += n) await Promise.all(list.slice(i, i + n).map(fn));
}

// ---- 审计日志 ----
const audit = (env, req, user, action, detail = '') =>
  env.DB.prepare('INSERT INTO audit(ts,user,action,detail,ip) VALUES(?,?,?,?,?)')
    .bind(Date.now(), user, action, clip(detail, 300), req.headers.get('cf-connecting-ip') || '').run().catch(() => {});

const dev = (b) => {
  const name = clip(b.name, 80), address = clip(b.address, 255);
  if (!name || !address) return null;
  return [name, clip(b.grp, 40) || '默认分组', clip(b.type, 40),
    PORTS[b.protocol] ? b.protocol : 'https', address, clip(b.port, 5), clip(b.note, 300), b.monitor ? 1 : 0];
};

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url), p = url.pathname, m = req.method;
    if (!p.startsWith('/api/')) return env.ASSETS.fetch(req);
    const DB = env.DB;
    const A = (user, action, detail) => ctx.waitUntil(audit(env, req, user, action, detail));
    try {
      // ---- 登录 / 退出 ----
      if (p === '/api/login' && m === 'POST') {
        const { username = '', password = '' } = await req.json();
        const n = await DB.prepare('SELECT COUNT(*) c FROM users').first();
        if (n.c === 0 && env.ADMIN_USER && env.ADMIN_PASS) {   // 首次启动自动创建管理员
          const salt = crypto.randomUUID();
          await DB.prepare('INSERT INTO users VALUES (?,?,?,?)')
            .bind(env.ADMIN_USER, salt, await pbkdf2(env.ADMIN_PASS, salt), 'admin').run();
        }
        const u = await DB.prepare('SELECT * FROM users WHERE username=?').bind(username).first();
        const ok = u && eq(await pbkdf2(password, u.salt), u.hash);
        if (!ok) { A(clip(username, 32) || '-', 'login_fail'); return J({ error: '用户名或密码错误' }, 401); }
        A(u.username, 'login');
        const pl = urlsafe(btoa(`${u.username}|${Date.now() + 12 * 3600e3}`));
        const tok = `${pl}.${await sign(env, pl)}`;
        return J({ ok: true }, 200, {
          'set-cookie': `s=${tok}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200` });
      }
      if (p === '/api/logout') {
        const s = await session(req, env);
        if (s) A(s.u, 'logout');
        return J({ ok: true }, 200, { 'set-cookie': 's=; Max-Age=0; Path=/' });
      }

      // ---- 以下需要登录 ----
      const me = await session(req, env);
      if (!me) return J({ error: 'unauthorized' }, 401);
      const needAdmin = () => (me.role === 'admin' ? null : J({ error: '需要管理员权限' }, 403));

      if (p === '/api/me') return J(me);

      if (p === '/api/settings') {
        if (m === 'GET') {
          const r = await DB.prepare('SELECT k,v FROM settings').all();
          return J(Object.fromEntries(r.results.map((x) => [x.k, x.v])));
        }
        if (m === 'PUT') {
          const d = needAdmin(); if (d) return d;
          const b = await req.json();
          for (const k of ['title', 'notice'])
            if (k in b) await DB.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v')
              .bind(k, clip(b[k], 500)).run();
          A(me.u, 'settings_update', JSON.stringify(b));
          return J({ ok: true });
        }
      }

      if (p === '/api/devices') {
        if (m === 'GET') return J((await DB.prepare('SELECT * FROM devices ORDER BY grp, name').all()).results);
        if (m === 'POST') {
          const d = needAdmin(); if (d) return d;
          const v = dev(await req.json());
          if (!v) return J({ error: '名称和地址必填' }, 400);
          await DB.prepare('INSERT INTO devices(name,grp,type,protocol,address,port,note,monitor) VALUES(?,?,?,?,?,?,?,?)').bind(...v).run();
          A(me.u, 'device_add', `${v[0]} (${v[4]})`);
          return J({ ok: true });
        }
      }
      let mm = p.match(/^\/api\/devices\/(\d+)$/);
      if (mm) {
        const d = needAdmin(); if (d) return d;
        const old = await DB.prepare('SELECT name,address FROM devices WHERE id=?').bind(mm[1]).first();
        if (!old) return J({ error: '设备不存在' }, 404);
        if (m === 'DELETE') {
          await DB.prepare('DELETE FROM devices WHERE id=?').bind(mm[1]).run();
          A(me.u, 'device_delete', `${old.name} (${old.address})`);
          return J({ ok: true });
        }
        if (m === 'PUT') {
          const v = dev(await req.json());
          if (!v) return J({ error: '名称和地址必填' }, 400);
          await DB.prepare('UPDATE devices SET name=?,grp=?,type=?,protocol=?,address=?,port=?,note=?,monitor=?,status=NULL,latency=NULL,checked_at=NULL WHERE id=?')
            .bind(...v, mm[1]).run();
          A(me.u, 'device_update', `${old.name} → ${v[0]} (${v[4]})`);
          return J({ ok: true });
        }
      }

      // 单设备状态检测(所有登录用户可用)
      mm = p.match(/^\/api\/check\/(\d+)$/);
      if (mm && m === 'POST') {
        const d = await DB.prepare('SELECT * FROM devices WHERE id=?').bind(mm[1]).first();
        return d ? J(await check(env, d)) : J({ error: '设备不存在' }, 404);
      }
      // 记录"打开设备"
      mm = p.match(/^\/api\/open\/(\d+)$/);
      if (mm && m === 'POST') {
        const d = await DB.prepare('SELECT name,address FROM devices WHERE id=?').bind(mm[1]).first();
        if (d) A(me.u, 'open_device', `${d.name} (${d.address})`);
        return J({ ok: true });
      }

      if (p === '/api/audit' && m === 'GET') {
        const d = needAdmin(); if (d) return d;
        const before = +url.searchParams.get('before') || Number.MAX_SAFE_INTEGER;
        const limit = Math.min(+url.searchParams.get('limit') || 100, 200);
        const r = await DB.prepare('SELECT id,ts,user,action,detail,ip FROM audit WHERE id<? ORDER BY id DESC LIMIT ?')
          .bind(before, limit).all();
        return J(r.results);
      }

      if (p === '/api/users') {
        const d = needAdmin(); if (d) return d;
        if (m === 'GET') return J((await DB.prepare('SELECT username, role FROM users ORDER BY username').all()).results);
        if (m === 'POST') {   // 新增用户;用户名已存在则重置密码/角色
          const b = await req.json();
          if (!/^[A-Za-z0-9_.-]{2,32}$/.test(b.username || '')) return J({ error: '用户名仅限字母数字_.-,2-32位' }, 400);
          if ((b.password || '').length < 8) return J({ error: '密码至少8位' }, 400);
          const salt = crypto.randomUUID(), role = b.role === 'admin' ? 'admin' : 'viewer';
          await DB.prepare('INSERT INTO users VALUES(?,?,?,?) ON CONFLICT(username) DO UPDATE SET salt=excluded.salt, hash=excluded.hash, role=excluded.role')
            .bind(b.username, salt, await pbkdf2(b.password, salt), role).run();
          A(me.u, 'user_save', `${b.username} (${role})`);
          return J({ ok: true });
        }
      }
      mm = p.match(/^\/api\/users\/([^/]+)$/);
      if (mm && m === 'DELETE') {
        const d = needAdmin(); if (d) return d;
        const name = decodeURIComponent(mm[1]);
        if (name === me.u) return J({ error: '不能删除自己' }, 400);
        await DB.prepare('DELETE FROM users WHERE username=?').bind(name).run();
        A(me.u, 'user_delete', name);
        return J({ ok: true });
      }
      return J({ error: 'not found' }, 404);
    } catch (e) {
      return J({ error: '服务器错误' }, 500);
    }
  },

  // 定时任务:检测最久没检测的 40 台设备 + 清理旧日志
  async scheduled(ev, env, ctx) {
    ctx.waitUntil((async () => {
      const r = await env.DB.prepare('SELECT * FROM devices WHERE monitor=1 ORDER BY COALESCE(checked_at,0) LIMIT 40').all();
      await inBatches(r.results, (d) => check(env, d));
      await env.DB.prepare('DELETE FROM audit WHERE ts<?').bind(Date.now() - 180 * 864e5).run();
    })());
  },
};
