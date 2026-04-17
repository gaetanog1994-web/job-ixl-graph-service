import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import neo4j from "neo4j-driver";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

function log(level, event, meta = {}) {
  const payload = {
    ts: new Date().toISOString(),
    level,
    service: "graph-service",
    event,
    ...meta,
  };
  const line = JSON.stringify(payload);
  if (level === "ERROR") console.error(line);
  else if (level === "WARN") console.warn(line);
  else console.log(line);
}

log("INFO", "boot");

const PORT = process.env.PORT || 8787;
const APP_ENV = (process.env.APP_ENV ?? (process.env.NODE_ENV === "production" ? "production" : "development"))
  .toLowerCase();
const IS_PRODUCTION = APP_ENV === "production";
const IS_DEVELOPMENT = APP_ENV === "development";
const ENABLE_DEBUG_ENDPOINTS =
  !IS_PRODUCTION &&
  (
    process.env.ENABLE_DEBUG_ENDPOINTS === "true" ||
    (IS_DEVELOPMENT && process.env.ENABLE_DEBUG_ENDPOINTS !== "false")
  );
const ENABLE_HARNESS_ENDPOINTS =
  !IS_PRODUCTION &&
  (
    process.env.ENABLE_HARNESS_ENDPOINTS === "true" ||
    (IS_DEVELOPMENT && process.env.ENABLE_HARNESS_ENDPOINTS !== "false")
  );

// Neo4j
const NEO4J_URI = process.env.NEO4J_URI;
const NEO4J_USER = process.env.NEO4J_USER;
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD;

// Token “legacy” per chiamate dal frontend (x-graph-token)
const GRAPH_SERVICE_TOKEN = process.env.GRAPH_SERVICE_TOKEN;

// Supabase admin (per validare Bearer token + controllo admin in tabella app_admins)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!NEO4J_URI || !NEO4J_USER || !NEO4J_PASSWORD) {
  log("ERROR", "missing_env_neo4j");
  process.exit(1);
}

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  log("ERROR", "missing_env_supabase");
  process.exit(1);
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const driver = neo4j.driver(
  NEO4J_URI,
  neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD)
);

function rejectFeatureDisabled(res, code, message) {
  return res.status(403).json({
    status: "ERROR",
    code,
    message,
  });
}

function requireDebugEnabled(res) {
  if (ENABLE_DEBUG_ENDPOINTS) return true;
  rejectFeatureDisabled(
    res,
    "DEBUG_DISABLED",
    "Debug endpoints are disabled for this environment."
  );
  return false;
}

function requireHarnessEnabled(res) {
  if (ENABLE_HARNESS_ENDPOINTS) return true;
  rejectFeatureDisabled(
    res,
    "HARNESS_DISABLED",
    "Harness endpoints are disabled. Set ENABLE_HARNESS_ENDPOINTS=true only in controlled dev/staging."
  );
  return false;
}

async function ensureNeo4jReady(retries = 20) {
  try {
    await driver.verifyConnectivity();
    return;
  } catch {
    if (retries <= 0) throw new Error("Neo4j not ready");
    log("WARN", "neo4j_sleeping_retry", { retriesRemaining: retries });
    await new Promise((r) => setTimeout(r, 2000));
    return ensureNeo4jReady(retries - 1);
  }
}

async function ensureNeo4jOrWaitResponse(res, operation, scope = null) {
  try {
    await ensureNeo4jReady(20);
    return true;
  } catch (e) {
    log("WARN", "neo4j_wait", {
      operation,
      companyId: scope?.companyId ?? null,
      perimeterId: scope?.perimeterId ?? null,
      reason: e?.message ?? "Neo4j not ready",
    });
    res.status(503).set("Retry-After", "10").json({
      status: "WAIT",
      code: "NEO4J_SLEEPING",
      message: "Neo4j is waking up, retry in a few seconds",
      ...(scope ? { companyId: scope.companyId, perimeterId: scope.perimeterId } : {}),
    });
    return false;
  }
}

/**
 * Ritorna:
 * - { mode: "token" } se header x-graph-token valido (richiede GRAPH_SERVICE_TOKEN settato)
 * - { mode: "supabase", userId } se Authorization Bearer valido
 * - null se non autenticato
 */
async function resolveAuth(req) {
  // 1) legacy token mode (x-graph-token)
  const token = req.header("x-graph-token");
  if (token && GRAPH_SERVICE_TOKEN && token === GRAPH_SERVICE_TOKEN) {
    return { mode: "token" };
  }

  // 2) Bearer token mode (Supabase)
  const auth = req.header("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;

  const jwt = m[1];
  const { data, error } = await supabaseAdmin.auth.getUser(jwt);
  if (error || !data?.user) return null;

  return { mode: "supabase", userId: data.user.id };
}

async function requireAdmin(req, res, next) {
  try {
    const auth = await resolveAuth(req);
    if (!auth) return res.status(401).json({ status: "ERROR", message: "Unauthorized" });

    // se arriva con x-graph-token, lo consideriamo admin (legacy)
    if (auth.mode === "token") return next();

    // altrimenti check su tabella app_admins
    const { data, error } = await supabaseAdmin
      .from("app_admins")
      .select("user_id")
      .eq("user_id", auth.userId)
      .maybeSingle();

    if (error) return res.status(500).json({ status: "ERROR", message: error.message });
    if (!data) return res.status(403).json({ status: "ERROR", message: "Admin only" });

    return next();
  } catch (err) {
    return res.status(500).json({ status: "ERROR", message: err.message || "Unknown error" });
  }
}

async function isAdminUserId(userId) {
  const { data, error } = await supabaseAdmin
    .from("app_admins")
    .select("user_id")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) throw new Error(error.message);
  return !!data;
}

/**
 * Require authentication and (optionally) ownership of a resource.
 * - legacy token mode (x-graph-token) is treated as admin
 * - bearer mode validates via Supabase and can be constrained to the same userId
 */
function requireAuth({ allowLegacyTokenAsAdmin = true } = {}) {
  return async (req, res, next) => {
    try {
      const auth = await resolveAuth(req);
      if (!auth) return res.status(401).json({ status: "ERROR", message: "Unauthorized" });

      // legacy token mode
      if (auth.mode === "token") {
        req.auth = { mode: "token", isAdmin: !!allowLegacyTokenAsAdmin };
        return next();
      }

      // bearer mode
      const admin = await isAdminUserId(auth.userId);
      req.auth = { mode: "supabase", userId: auth.userId, isAdmin: admin };
      return next();
    } catch (err) {
      return res.status(500).json({ status: "ERROR", message: err.message || "Unknown error" });
    }
  };
}

/* ----------------------------------
   Health check
---------------------------------- */
app.get("/health", async (_req, res) => {
  try {
    await ensureNeo4jReady(0);
    res.json({ status: "OK", neo4j: "ready" });
  } catch {
    res.status(503).json({ status: "ERROR", neo4j: "sleeping" });
  }
});

// Backward compatible health endpoint expected by the FE
app.get("/api/health", async (req, res) => {
  // same output shape as /health
  return app._router.handle({ ...req, url: "/health", originalUrl: "/health" }, res, () => { });
});

/* ----------------------------------
   DEBUG: Supabase backend config
   (TEMPORARY – remove after check)
---------------------------------- */
app.get("/api/_debug/supabase", (_req, res) => {
  if (!requireDebugEnabled(res)) return;
  res.json({
    supabaseUrl: SUPABASE_URL,
    hasServiceRole: !!SUPABASE_SERVICE_ROLE_KEY,
  });
});

/* ----------------------------------
   DEBUG: Auth check (TEMPORARY)
   - Does NOT print the token
   - Returns Supabase getUser() error details
---------------------------------- */
app.post("/api/_debug/auth-check", async (req, res) => {
  if (!requireDebugEnabled(res)) return;
  try {
    const authHeader = req.header("authorization") || "";
    const m = authHeader.match(/^Bearer\s+(.+)$/i);
    if (!m) {
      return res.status(400).json({
        ok: false,
        reason: "missing_bearer",
        hasAuthHeader: !!authHeader,
      });
    }

    const jwt = m[1];

    // Basic metadata (safe)
    const parts = jwt.split(".");
    const tokenShapeOk = parts.length === 3;

    // Call Supabase to validate token
    const { data, error } = await supabaseAdmin.auth.getUser(jwt);

    return res.json({
      ok: !error && !!data?.user,
      tokenShapeOk,
      user: data?.user ? { id: data.user.id, email: data.user.email } : null,
      error: error
        ? {
          message: error.message,
          status: error.status,
          name: error.name,
        }
        : null,
    });
  } catch (e) {
    return res.status(500).json({
      ok: false,
      reason: e?.message || "unknown_error",
    });
  }
});


function requireSelfOrAdmin(paramName = "userId") {
  return async (req, res, next) => {
    try {
      const auth = req.auth;
      if (!auth) return res.status(401).json({ status: "ERROR", message: "Unauthorized" });

      // legacy token => treat as admin
      if (auth.mode === "token") return next();

      const requestedUserId = req.params?.[paramName];
      if (!requestedUserId) {
        return res.status(400).json({ status: "ERROR", message: `Missing param ${paramName}` });
      }

      if (auth.userId === requestedUserId) return next();

      const admin = await isAdminUserId(auth.userId);
      if (!admin) return res.status(403).json({ status: "ERROR", message: "Forbidden" });

      return next();
    } catch (err) {
      return res
        .status(500)
        .json({ status: "ERROR", message: err?.message || "Unknown error" });
    }
  };
}

function asNonEmptyString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}

function resolveTenantScope(req) {
  const companyId =
    asNonEmptyString(req.body?.companyId) ||
    asNonEmptyString(req.body?.company_id) ||
    asNonEmptyString(req.query?.companyId) ||
    asNonEmptyString(req.query?.company_id) ||
    asNonEmptyString(req.header("x-company-id"));
  const perimeterId =
    asNonEmptyString(req.body?.perimeterId) ||
    asNonEmptyString(req.body?.perimeter_id) ||
    asNonEmptyString(req.query?.perimeterId) ||
    asNonEmptyString(req.query?.perimeter_id) ||
    asNonEmptyString(req.header("x-perimeter-id"));

  if (!companyId || !perimeterId) return null;
  return { companyId, perimeterId };
}

function getTenantScopeOrRespond(req, res) {
  const scope = resolveTenantScope(req);
  if (!scope) {
    res.status(400).json({
      status: "ERROR",
      message: "companyId/perimeterId (or company_id/perimeter_id) are required",
      code: "TENANT_SCOPE_REQUIRED",
    });
    return null;
  }
  return scope;
}

function resolveGraphNamespace(scope) {
  return {
    companyId: scope.companyId,
    perimeterId: scope.perimeterId,
    tenantKey: `${scope.companyId}::${scope.perimeterId}`,
    // futura evoluzione: dbName dinamico per database-per-tenant
    dbName: null,
  };
}

/* ----------------------------------
   APP API (used by the frontend)
   - keeps Supabase as source of truth
   - avoids writing business logic in Supabase
---------------------------------- */

// Admin: reset all active users + clear applications (dashboard reset)
app.post(
  "/api/admin/reset-active-users",
  requireAuth(),
  requireAdmin,
  async (_req, res) => {
    if (!requireHarnessEnabled(res)) return;
    try {
      // 1) set all users inactive
      const { error: upErr } = await supabaseAdmin
        .from("users")
        .update({ availability_status: "inactive" })
        .neq("availability_status", "inactive"); // aggiorna solo chi non è già inactive

      if (upErr) {
        return res.status(500).json({ status: "ERROR", message: upErr.message });
      }

      // 2) delete all applications (outgoing + incoming)
      const { error: delErr } = await supabaseAdmin
        .from("applications")
        .delete()
        .neq("id", "00000000-0000-0000-0000-000000000000"); // trucco per "delete all"

      if (delErr) {
        return res.status(500).json({ status: "ERROR", message: delErr.message });
      }

      return res.json({ status: "OK" });
    } catch (err) {
      return res.status(500).json({
        status: "ERROR",
        message: err?.message || "Unknown error",
      });
    }
  }
);


// Deactivate a user and cleanup related applications
app.post(
  "/api/users/:userId/deactivate",
  requireAuth(),
  requireSelfOrAdmin("userId"),
  async (req, res) => {
    const userId = req.params.userId;

    try {
      // 1) set user inactive
      const { error: upErr } = await supabaseAdmin
        .from("users")
        .update({ availability_status: "inactive" })
        .eq("id", userId);

      if (upErr) {
        return res.status(500).json({ status: "ERROR", message: upErr.message });
      }

      // 2) delete outgoing + incoming applications
      const { error: delErr } = await supabaseAdmin
        .from("applications")
        .delete()
        .or(`user_id.eq.${userId}`);

      if (delErr) {
        return res.status(500).json({ status: "ERROR", message: delErr.message });
      }

      return res.json({ status: "OK" });
    } catch (err) {
      return res
        .status(500)
        .json({ status: "ERROR", message: err?.message || "Unknown error" });
    }
  }
);

// Reorder applications for a user
app.post(
  "/api/users/:userId/reorder-applications",
  requireAuth(),
  requireSelfOrAdmin("userId"),
  async (req, res) => {
    const userId = req.params.userId;
    const updates = req.body?.updates;

    if (!Array.isArray(updates) || updates.length === 0) {
      return res.status(400).json({ status: "ERROR", message: "Invalid updates" });
    }

    try {
      // Validate and apply updates
      for (const u of updates) {
        if (!u || !Array.isArray(u.app_ids) || typeof u.priority !== "number") {
          return res.status(400).json({ status: "ERROR", message: "Invalid updates payload" });
        }

        const { error } = await supabaseAdmin
          .from("applications")
          .update({ priority: u.priority })
          .in("id", u.app_ids)
          .eq("user_id", userId);

        if (error) {
          return res.status(500).json({ status: "ERROR", message: error.message });
        }
      }

      return res.json({ status: "OK" });
    } catch (err) {
      return res
        .status(500)
        .json({ status: "ERROR", message: err?.message || "Unknown error" });
    }
  }
);

/* ----------------------------------
   Neo4j Warmup (Admin only)
---------------------------------- */
app.post("/neo4j/warmup", requireAdmin, async (_req, res) => {
  const scope = getTenantScopeOrRespond(_req, res);
  if (!scope) return;
  const ok = await ensureNeo4jOrWaitResponse(res, "neo4j_warmup", scope);
  if (!ok) return;
  res.json({
    status: "OK",
    neo4j: "ready",
    companyId: scope.companyId,
    perimeterId: scope.perimeterId,
  });
});

/* ----------------------------------
   Build Graph (Admin only)
---------------------------------- */
app.post("/build-graph", requireAdmin, async (req, res) => {
  const scope = getTenantScopeOrRespond(req, res);
  if (!scope) return;
  const warm = await ensureNeo4jOrWaitResponse(res, "build_graph", scope);
  if (!warm) return;
  const namespace = resolveGraphNamespace(scope);
  const { applications, usersById } = req.body || {};
  const scopedApps = Array.isArray(applications)
    ? applications
      .filter((app) => app?.user_id && app?.target_user_id)
      .filter((app) => {
        const appCompanyId = app?.company_id ?? app?.companyId ?? null;
        const appPerimeterId = app?.perimeter_id ?? app?.perimeterId ?? null;
        // Defense-in-depth: discard cross-tenant payload rows if a caller sends mixed data.
        if (appCompanyId && String(appCompanyId) !== namespace.companyId) return false;
        if (appPerimeterId && String(appPerimeterId) !== namespace.perimeterId) return false;
        return true;
      })
      .map((app) => ({
        user_id: String(app.user_id),
        target_user_id: String(app.target_user_id),
        priority: app.priority ?? null,
      }))
    : [];
  const session = driver.session();

  try {
    const out = await session.writeTransaction(async (tx) => {
      try {
        await tx.run(
          `
          CREATE CONSTRAINT person_tenant_identity IF NOT EXISTS
          FOR (p:Person)
          REQUIRE (p.company_id, p.perimeter_id, p.user_id) IS UNIQUE
          `
        );
      } catch (constraintErr) {
        // compat with older Neo4j versions / limited privileges
        console.warn("Constraint creation skipped:", constraintErr?.message || constraintErr);
      }

      await tx.run(
        `
        MATCH (n:Person {company_id: $companyId, perimeter_id: $perimeterId})
        DETACH DELETE n
        `,
        namespace
      );

      await tx.run(
        `
        UNWIND $apps AS app
        MERGE (a:Person {
          company_id: $companyId,
          perimeter_id: $perimeterId,
          user_id: app.user_id
        })
        SET a.id = app.user_id,
            a.company_id = $companyId,
            a.perimeter_id = $perimeterId,
            a.user_id = app.user_id,
            a.tenant_key = $tenantKey
        SET a.full_name = coalesce($usersById[app.user_id], a.full_name)

        MERGE (b:Person {
          company_id: $companyId,
          perimeter_id: $perimeterId,
          user_id: app.target_user_id
        })
        SET b.id = app.target_user_id,
            b.company_id = $companyId,
            b.perimeter_id = $perimeterId,
            b.user_id = app.target_user_id,
            b.tenant_key = $tenantKey
        SET b.full_name = coalesce($usersById[app.target_user_id], b.full_name)

        MERGE (a)-[r:CANDIDATO_A {
          company_id: $companyId,
          perimeter_id: $perimeterId
        }]->(b)
        SET r.priority = app.priority,
            r.company_id = $companyId,
            r.perimeter_id = $perimeterId,
            r.tenant_key = $tenantKey
        `,
        { ...namespace, apps: scopedApps, usersById: usersById || {} }
      );

      const nodes = await tx.run(
        `
        MATCH (n:Person {company_id: $companyId, perimeter_id: $perimeterId})
        RETURN count(n) AS c
        `,
        namespace
      );
      const rels = await tx.run(
        `
        MATCH (:Person {company_id: $companyId, perimeter_id: $perimeterId})
              -[r:CANDIDATO_A {company_id: $companyId, perimeter_id: $perimeterId}]->
              (:Person {company_id: $companyId, perimeter_id: $perimeterId})
        RETURN count(r) AS c
        `,
        namespace
      );

      return {
        nodes: nodes.records[0].get("c").toNumber(),
        relationships: rels.records[0].get("c").toNumber(),
      };
    });

    res.json({
      status: "OK",
      companyId: scope.companyId,
      perimeterId: scope.perimeterId,
      ...out,
    });
  } catch (err) {
    log("ERROR", "build_graph_failed", {
      companyId: scope.companyId,
      perimeterId: scope.perimeterId,
      message: err?.message || "Unknown error",
    });
    res.status(500).json({ status: "ERROR", message: err.message || "Unknown error" });
  } finally {
    await session.close();
  }
});

/* ----------------------------------
   Chains (Admin only)
---------------------------------- */
app.post("/graph/chains", requireAdmin, async (req, res) => {
  const scope = getTenantScopeOrRespond(req, res);
  if (!scope) return;
  const warm = await ensureNeo4jOrWaitResponse(res, "graph_chains", scope);
  if (!warm) return;
  const namespace = resolveGraphNamespace(scope);
  const session = driver.session();

  try {
    const reqMaxLen = Number(req.body?.maxLen ?? 10);
    const maxLen = Number.isFinite(reqMaxLen) ? Math.min(15, Math.max(2, reqMaxLen)) : 10;
    const cypher = `
      MATCH path = (n:Person)-[rels:CANDIDATO_A*2..${maxLen}]->(n)
      WHERE n.company_id = $companyId
        AND n.perimeter_id = $perimeterId
      WITH path, nodes(path) AS ns, rels
      WHERE size(ns[0..-1]) = size(apoc.coll.toSet(ns[0..-1]))
        AND ALL(n IN ns WHERE n.company_id = $companyId AND n.perimeter_id = $perimeterId)
        AND ALL(r IN rels WHERE r.company_id = $companyId AND r.perimeter_id = $perimeterId)
      WITH
        ns[0..-1] AS persons,
        rels,
        CASE
          WHEN ANY(r IN rels WHERE r.priority IS NULL)
          THEN null
          ELSE round(
            reduce(total = 0.0, r IN rels | total + toFloat(r.priority))
            / size(rels)
            * 100
          ) / 100
        END AS avgPriority
      RETURN
        [p IN persons | p.user_id] AS users,
        [p IN persons | coalesce(p.full_name, p.id)] AS peopleNames,
        size(persons) AS length,
        avgPriority
    `;

    const result = await session.run(cypher, namespace);

    const seen = new Set();
    const chains = result.records
      .map((rec) => {
        const users = rec.get("users");
        const peopleNames = rec.get("peopleNames");
        const key = users.slice().sort().join("|");
        return {
          key,
          users,
          peopleNames,
          length: rec.get("length").toNumber(),
          avgPriority: rec.get("avgPriority"),
        };
      })
      .filter((c) => {
        if (seen.has(c.key)) return false;
        seen.add(c.key);
        return true;
      })
      .map(({ key, ...rest }) => rest);

    res.json({
      status: "OK",
      companyId: scope.companyId,
      perimeterId: scope.perimeterId,
      chains,
    });
  } catch (err) {
    log("ERROR", "graph_chains_failed", {
      companyId: scope.companyId,
      perimeterId: scope.perimeterId,
      message: err?.message || "Unknown error",
    });
    res.status(500).json({ status: "ERROR", message: err.message || "Unknown error" });
  } finally {
    await session.close();
  }
});

/* ----------------------------------
   Graph Summary (RELATIONS) (Admin only)
   -> serve ad AdminCandidatures (tabella Da/A/Priorità)
---------------------------------- */
app.post("/graph/summary", requireAdmin, async (req, res) => {
  const scope = getTenantScopeOrRespond(req, res);
  if (!scope) return;
  const warm = await ensureNeo4jOrWaitResponse(res, "graph_summary", scope);
  if (!warm) return;
  const namespace = resolveGraphNamespace(scope);
  const session = driver.session();

  try {
    const cypher = `
      MATCH (a:Person)-[r:CANDIDATO_A]->(b:Person)
      WHERE a.company_id = $companyId
        AND a.perimeter_id = $perimeterId
        AND b.company_id = $companyId
        AND b.perimeter_id = $perimeterId
        AND r.company_id = $companyId
        AND r.perimeter_id = $perimeterId
      RETURN 
        coalesce(a.full_name, a.id) AS from_name,
        coalesce(b.full_name, b.id) AS to_name,
        r.priority AS priority
      ORDER BY from_name, to_name
    `;

    const result = await session.run(cypher, namespace);

    const relationships = result.records.map((rec) => ({
      from_name: rec.get("from_name"),
      to_name: rec.get("to_name"),
      priority: rec.get("priority"),
    }));

    res.json({
      status: "OK",
      companyId: scope.companyId,
      perimeterId: scope.perimeterId,
      relationships,
    });
  } catch (err) {
    log("ERROR", "graph_summary_failed", {
      companyId: scope.companyId,
      perimeterId: scope.perimeterId,
      message: err?.message || "Unknown error",
    });
    res.status(500).json({ status: "ERROR", message: err.message || "Unknown error" });
  } finally {
    await session.close(); // ✅ fondamentale
  }
});

app.post("/api/test-scenarios/:id/initialize", requireAdmin, async (req, res) => {
  if (!requireHarnessEnabled(res)) return;
  const scenarioId = req.params.id;

  // Risposta immediata: evita timeouts e rende l’API "prodotto-like"
  res.status(202).json({ status: "accepted", scenarioId });

  setImmediate(async () => {
    try {
      console.log("[initialize] start", { scenarioId });

      // 1) Carica le candidature scenario (isolated)
      const { data: scenApps, error: scenErr } = await supabaseAdmin
        .from("test_scenario_applications")
        .select("user_id, position_id, priority")
        .eq("scenario_id", scenarioId);

      if (scenErr) throw new Error(`test_scenario_applications: ${scenErr.message}`);
      if (!scenApps || scenApps.length === 0) {
        console.log("[initialize] no scenario applications found", { scenarioId });
        return;
      }

      // 2) Reset: tutti inactive + delete applications
      const { error: upErr } = await supabaseAdmin
        .from("users")
        .update({ availability_status: "inactive" })
        .neq("availability_status", "inactive");
      if (upErr) throw new Error(`users inactive: ${upErr.message}`);

      const { error: delErr } = await supabaseAdmin
        .from("applications")
        .delete()
        .neq("id", "00000000-0000-0000-0000-000000000000");
      if (delErr) throw new Error(`delete applications: ${delErr.message}`);

      // 3) Inserisci applications reali (schema: user_id -> position_id)
      const appRows = scenApps.map((a) => ({
        user_id: a.user_id,
        position_id: a.position_id,
        priority: a.priority,
      }));

      const { error: insErr } = await supabaseAdmin.from("applications").insert(appRows);
      if (insErr) throw new Error(`insert applications: ${insErr.message}`);

      // 4) Attiva utenti coinvolti:
      //    - tutti i candidati (user_id)
      //    - tutti gli occupanti delle posizioni target (positions.occupied_by)
      const candidateUserIds = [...new Set(appRows.map((r) => r.user_id))];
      const positionIds = [...new Set(appRows.map((r) => r.position_id).filter(Boolean))];

      const { data: posRows, error: posErr } = await supabaseAdmin
        .from("positions")
        .select("id, occupied_by")
        .in("id", positionIds);

      if (posErr) throw new Error(`positions (for activation): ${posErr.message}`);

      const targetUserIds = [...new Set((posRows ?? []).map((p) => p.occupied_by).filter(Boolean))];
      const activeUserIds = [...new Set([...candidateUserIds, ...targetUserIds])];

      const { error: actErr } = await supabaseAdmin
        .from("users")
        .update({ availability_status: "active" })
        .in("id", activeUserIds);

      if (actErr) throw new Error(`set active users: ${actErr.message}`);

      console.log("[initialize] applied scenario", {
        scenarioId,
        applicationsInserted: appRows.length,
        activeUsers: activeUserIds.length,
      });

      console.log("[initialize] done", { scenarioId });
    } catch (e) {
      console.error("[initialize] failed", {
        scenarioId,
        err: e?.message,
        stack: e?.stack,
      });
    }
  });
});



/* ----------------------------------
   DEBUG: Inspect scenario data pipeline
   (TEMPORARY – remove after check)
---------------------------------- */
app.get("/api/_debug/scenario/:id/inspect", requireAdmin, async (req, res) => {
  if (!requireDebugEnabled(res)) return;
  const scenarioId = req.params.id;



  // 1) scenario apps
  const { data: scenApps, error: scenErr } = await supabaseAdmin
    .from("test_scenario_applications")
    .select("id, scenario_id, user_id, position_id, priority")
    .eq("scenario_id", scenarioId);

  if (scenErr) return res.status(500).json({ status: "ERROR", where: "test_scenario_applications", message: scenErr.message });

  const positionIds = [...new Set((scenApps ?? []).map(a => a.position_id).filter(Boolean))];

  // 2) positions lookup
  const { data: posRows, error: posErr } = await supabaseAdmin
    .from("positions")
    .select("id, occupied_by")
    .in("id", positionIds);

  if (posErr) return res.status(500).json({ status: "ERROR", where: "positions", message: posErr.message });

  const foundPosIds = new Set((posRows ?? []).map(p => p.id));
  const missingPositions = positionIds.filter(id => !foundPosIds.has(id));
  const positionsWithoutOccupant = (posRows ?? []).filter(p => !p.occupied_by).map(p => p.id);

  // 3) derived appRows count (what would be inserted)
  const posToTarget = new Map((posRows ?? []).map(p => [p.id, p.occupied_by]));
  const derived = (scenApps ?? []).map(a => ({
    user_id: a.user_id,
    position_id: a.position_id,
    target_user_id: posToTarget.get(a.position_id) || null,
    priority: a.priority,
  }));
  const insertable = derived.filter(r => r.target_user_id);

  return res.json({
    status: "OK",
    scenarioId,
    scenAppsCount: scenApps?.length ?? 0,
    positionIdsCount: positionIds.length,
    positionsFoundCount: posRows?.length ?? 0,
    missingPositionsCount: missingPositions.length,
    missingPositions,
    positionsWithoutOccupantCount: positionsWithoutOccupant.length,
    positionsWithoutOccupant,
    derivedCount: derived.length,
    insertableCount: insertable.length,
    sample: {
      scenApp: scenApps?.[0] ?? null,
      position: posRows?.[0] ?? null,
      derived: derived?.[0] ?? null,
    },
  });
});


/* ----------------------------------
   DEBUG: Check current effects in DB
---------------------------------- */
app.get("/api/_debug/effects", requireAdmin, async (_req, res) => {
  if (!requireDebugEnabled(res)) return;
  try {
    const { data: activeUsers, error: auErr } = await supabaseAdmin
      .from("users")
      .select("id")
      .eq("availability_status", "active");

    if (auErr) {
      return res.status(500).json({ status: "ERROR", where: "users", message: auErr.message });
    }

    const { data: apps, error: appErr } = await supabaseAdmin
      .from("applications")
      .select("id, user_id, position_id, priority")
      .limit(50);

    if (appErr) {
      return res.status(500).json({ status: "ERROR", where: "applications", message: appErr.message });
    }

    return res.json({
      status: "OK",
      activeUsersCount: activeUsers?.length ?? 0,
      applicationsCount: apps?.length ?? 0,
      sampleApplication: apps?.[0] ?? null,
    });
  } catch (e) {
    return res.status(500).json({ status: "ERROR", message: e?.message || "Unknown error" });
  }
});

/* ----------------------------------
   DEBUG: Check applications columns
---------------------------------- */
app.get("/api/_debug/applications-columns", requireAdmin, async (_req, res) => {
  if (!requireDebugEnabled(res)) return;
  const { data, error } = await supabaseAdmin
    .from("applications")
    .select("*")
    .limit(1);

  if (error) return res.status(500).json({ status: "ERROR", message: error.message });

  const row = data?.[0] ?? null;
  return res.json({
    status: "OK",
    columns: row ? Object.keys(row) : [],
    sample: row,
  });
});

/* ----------------------------------
   Graph Summary (COUNTS) (Admin only)
---------------------------------- */
app.get("/graph/summary", requireAdmin, async (req, res) => {
  const scope = getTenantScopeOrRespond(req, res);
  if (!scope) return;
  const warm = await ensureNeo4jOrWaitResponse(res, "graph_summary_counts", scope);
  if (!warm) return;
  const namespace = resolveGraphNamespace(scope);
  const session = driver.session();

  try {
    const nodes = await session.run(
      `
      MATCH (n:Person {company_id: $companyId, perimeter_id: $perimeterId})
      RETURN count(n) AS c
      `,
      namespace
    );
    const rels = await session.run(
      `
      MATCH (:Person {company_id: $companyId, perimeter_id: $perimeterId})
            -[r:CANDIDATO_A {company_id: $companyId, perimeter_id: $perimeterId}]->
            (:Person {company_id: $companyId, perimeter_id: $perimeterId})
      RETURN count(r) AS c
      `,
      namespace
    );

    res.json({
      status: "OK",
      companyId: scope.companyId,
      perimeterId: scope.perimeterId,
      nodes: nodes.records[0].get("c").toNumber(),
      relationships: rels.records[0].get("c").toNumber(),
    });
  } catch (err) {
    log("ERROR", "graph_summary_counts_failed", {
      companyId: scope.companyId,
      perimeterId: scope.perimeterId,
      message: err?.message || "Unknown error",
    });
    res.status(500).json({ status: "ERROR", message: err.message || "Unknown error" });
  } finally {
    await session.close(); // ✅ fondamentale
  }
});

app.get("/api/_debug/routes", (_req, res) => {
  if (!requireDebugEnabled(res)) return;
  const routes = [];
  app._router.stack.forEach((layer) => {
    if (layer.route && layer.route.path) {
      const methods = Object.keys(layer.route.methods)
        .filter((m) => layer.route.methods[m])
        .map((m) => m.toUpperCase());
      routes.push({ path: layer.route.path, methods });
    }
  });
  res.json({ status: "OK", routes });
});


/* ----------------------------------
   START SERVER
---------------------------------- */
app.listen(Number(PORT), () => {
  log("INFO", "listen", { port: Number(PORT) });
});
