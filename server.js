import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import neo4j from "neo4j-driver";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));
console.log("🚀 GRAPH SERVICE BOOT — VERSION 2026-01-02 WARMUP");


const {
  PORT = 8787,
  NEO4J_URI,
  NEO4J_USER,
  NEO4J_PASSWORD,
  GRAPH_SERVICE_TOKEN,
} = process.env;

if (!NEO4J_URI || !NEO4J_USER || !NEO4J_PASSWORD) {
  console.error("❌ Missing Neo4j env vars");
  process.exit(1);
}

if (!GRAPH_SERVICE_TOKEN) {
  console.error("❌ Missing GRAPH_SERVICE_TOKEN");
  process.exit(1);
}

/* ----------------------------------
   Neo4j Driver
---------------------------------- */
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
    await new Promise(r => setTimeout(r, 2000));
    return ensureNeo4jReady(retries - 1);
  }
}



/* ----------------------------------
   Auth middleware
---------------------------------- */
function requireToken(req, res, next) {
  const token = req.header("x-graph-token");
  if (!token || token !== GRAPH_SERVICE_TOKEN) {
    return res.status(401).json({ status: "ERROR", message: "Unauthorized" });
  }
  next();
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


/* ----------------------------------
   Neo4j warmup
---------------------------------- */
app.post("/neo4j/warmup", requireToken, async (_req, res) => {
  try {
    await ensureNeo4jReady(20); // ⏱️ fino a ~30s
    res.json({ status: "OK", neo4j: "ready" });
  } catch (err) {
    res.status(503).json({
      status: "ERROR",
      message: "Neo4j still sleeping",
    });
  }
});
console.log("📌 Registering /neo4j/warmup route");


/* ----------------------------------
   BUILD GRAPH (RESET + REBUILD) — compat
---------------------------------- */
app.post("/build-graph", requireToken, async (req, res) => {
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

    const msg =
      err?.message?.includes("ServiceUnavailable")
        ? "Neo4j in avvio. Riprova tra qualche secondo."
        : err.message;

    res.status(500).json({ status: "ERROR", message: msg });
  } finally {
    await session.close();
  }
});



/* ----------------------------------
   FIND CHAINS (POST — DEFINITIVO)
---------------------------------- */
app.post("/graph/chains", requireToken, async (_req, res) => {
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
    res.status(500).json({
      status: "ERROR",
      message: err.message,
    });
  } finally {
    await session.close();
  }
});



/* ----------------------------------
   START SERVER
---------------------------------- */
app.listen(Number(PORT), () => {
  console.log(`🚀 Graph service listening on port ${PORT}`);
});
