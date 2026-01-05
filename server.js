import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import neo4j from "neo4j-driver";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

console.log("🚀 Graph Service Booting...");

const PORT = process.env.PORT || 8787;

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
  console.error("❌ Missing Neo4j env vars");
  process.exit(1);
}

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("❌ Missing Supabase env vars");
  process.exit(1);
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const driver = neo4j.driver(
  NEO4J_URI,
  neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD)
);

async function ensureNeo4jReady(retries = 20) {
  try {
    await driver.verifyConnectivity();
    return;
  } catch {
    if (retries <= 0) throw new Error("Neo4j not ready");
    console.warn("⏳ Neo4j sleeping… retrying");
    await new Promise((r) => setTimeout(r, 2000));
    return ensureNeo4jReady(retries - 1);
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
        .or(`user_id.eq.${userId},target_user_id.eq.${userId}`);

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
  try {
    await ensureNeo4jReady(20);
    res.json({ status: "OK", neo4j: "ready" });
  } catch {
    res.json({ status: "WAIT", message: "Neo4j is waking up" });
  }
});

/* ----------------------------------
   Build Graph (Admin only)
---------------------------------- */
app.post("/build-graph", requireAdmin, async (req, res) => {
  await ensureNeo4jReady();
  const { applications, usersById } = req.body || {};
  const session = driver.session();

  try {
    const out = await session.writeTransaction(async (tx) => {
      await tx.run("MATCH (n) DETACH DELETE n");

      await tx.run(
        `
        UNWIND $apps AS app
        MERGE (a:Person {id: app.user_id})
        SET a.full_name = coalesce($usersById[app.user_id], a.full_name)

        MERGE (b:Person {id: app.target_user_id})
        SET b.full_name = coalesce($usersById[app.target_user_id], b.full_name)

        MERGE (a)-[r:CANDIDATO_A]->(b)
        SET r.priority = app.priority
        `,
        { apps: applications || [], usersById: usersById || {} }
      );

      const nodes = await tx.run("MATCH (n:Person) RETURN count(n) AS c");
      const rels = await tx.run(
        "MATCH (:Person)-[r:CANDIDATO_A]->(:Person) RETURN count(r) AS c"
      );

      return {
        nodes: nodes.records[0].get("c").toNumber(),
        relationships: rels.records[0].get("c").toNumber(),
      };
    });

    res.json({ status: "OK", ...out });
  } catch (err) {
    console.error("Error in /build-graph:", err);
    res.status(500).json({ status: "ERROR", message: err.message || "Unknown error" });
  } finally {
    await session.close();
  }
});

/* ----------------------------------
   Chains (Admin only)
---------------------------------- */
app.post("/graph/chains", requireAdmin, async (_req, res) => {
  await ensureNeo4jReady();
  const session = driver.session();

  try {
    const cypher = `
      MATCH path = (p:Person)-[rels:CANDIDATO_A*2..10]->(p)
      WITH path, nodes(path) AS ns, rels
      WHERE size(ns[0..-1]) = size(apoc.coll.toSet(ns[0..-1]))
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
        [p IN persons | coalesce(p.full_name, p.id)] AS people,
        size(persons) AS length,
        avgPriority
    `;

    const result = await session.run(cypher);

    const seen = new Set();
    const chains = result.records
      .map((rec) => {
        const people = rec.get("people");
        const key = people.slice().sort().join("|");
        return {
          key,
          people,
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

    res.json({ status: "OK", chains });
  } catch (err) {
    console.error("Error in /graph/chains:", err);
    res.status(500).json({ status: "ERROR", message: err.message || "Unknown error" });
  } finally {
    await session.close();
  }
});

/* ----------------------------------
   Graph Summary (RELATIONS) (Admin only)
   -> serve ad AdminCandidatures (tabella Da/A/Priorità)
---------------------------------- */
app.post("/graph/summary", requireAdmin, async (_req, res) => {
  await ensureNeo4jReady(); // ✅ fondamentale
  const session = driver.session();

  try {
    const cypher = `
      MATCH (a:Person)-[r:CANDIDATO_A]->(b:Person)
      RETURN 
        coalesce(a.full_name, a.id) AS from_name,
        coalesce(b.full_name, b.id) AS to_name,
        r.priority AS priority
      ORDER BY from_name, to_name
    `;

    const result = await session.run(cypher);

    const relationships = result.records.map((rec) => ({
      from_name: rec.get("from_name"),
      to_name: rec.get("to_name"),
      priority: rec.get("priority"),
    }));

    res.json({ status: "OK", relationships });
  } catch (err) {
    console.error("Error in /graph/summary:", err);
    res.status(500).json({ status: "ERROR", message: err.message || "Unknown error" });
  } finally {
    await session.close(); // ✅ fondamentale
  }
});

/* ----------------------------------
   Graph Summary (COUNTS) (Admin only)
---------------------------------- */
app.get("/graph/summary", requireAdmin, async (_req, res) => {
  await ensureNeo4jReady(); // ✅ fondamentale
  const session = driver.session();

  try {
    const nodes = await session.run("MATCH (n:Person) RETURN count(n) AS c");
    const rels = await session.run(
      "MATCH (:Person)-[r:CANDIDATO_A]->(:Person) RETURN count(r) AS c"
    );

    res.json({
      status: "OK",
      nodes: nodes.records[0].get("c").toNumber(),
      relationships: rels.records[0].get("c").toNumber(),
    });
  } catch (err) {
    console.error("Error in GET /graph/summary:", err);
    res.status(500).json({ status: "ERROR", message: err.message || "Unknown error" });
  } finally {
    await session.close(); // ✅ fondamentale
  }
});

/* ----------------------------------
   START SERVER
---------------------------------- */
app.listen(Number(PORT), () => {
  console.log(`🚀 Graph Service listening on port ${PORT}`);
});
