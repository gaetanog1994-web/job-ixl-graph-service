import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import neo4j from "neo4j-driver";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

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
   Auth middleware
---------------------------------- */
function requireToken(req, res, next) {
  const token = req.header("x-graph-token");
  if (!token || token !== GRAPH_SERVICE_TOKEN) {
    return res.status(401).json({
      status: "ERROR",
      message: "Unauthorized",
    });
  }
  next();
}

/* ----------------------------------
   Health check
---------------------------------- */
app.get("/health", (_req, res) => {
  res.json({ status: "OK" });
});

/* ----------------------------------
   BUILD GRAPH (write / reset)
---------------------------------- */
app.post("/build-graph", requireToken, async (req, res) => {
  const { applications, usersById } = req.body || {};

  if (!Array.isArray(applications)) {
    return res.status(400).json({
      status: "ERROR",
      message: "`applications` must be an array",
    });
  }

  const driver = neo4j.driver(
    NEO4J_URI,
    neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD)
  );

  const session = driver.session();

  try {
    // Reset grafo derivato
    await session.run("MATCH (n) DETACH DELETE n");

    // Build nodi + relazioni
    await session.run(
      `
      UNWIND $apps AS app
      MERGE (a:Person {id: app.user_id})
      ON CREATE SET a.full_name = coalesce($usersById[app.user_id], null)
      ON MATCH  SET a.full_name = coalesce($usersById[app.user_id], a.full_name)

      MERGE (b:Person {id: app.target_user_id})
      ON CREATE SET b.full_name = coalesce($usersById[app.target_user_id], null)
      ON MATCH  SET b.full_name = coalesce($usersById[app.target_user_id], b.full_name)

      MERGE (a)-[r:CANDIDATO_A]->(b)
      SET r.priority = app.priority
      `,
      { apps: applications, usersById: usersById || {} }
    );

    const nodesRes = await session.run(
      "MATCH (n:Person) RETURN count(n) AS c"
    );
    const relsRes = await session.run(
      "MATCH (:Person)-[r:CANDIDATO_A]->(:Person) RETURN count(r) AS c"
    );

    const nodes = nodesRes.records[0].get("c").toNumber();
    const relationships = relsRes.records[0].get("c").toNumber();

    res.json({
      status: "OK",
      applications_processed: applications.length,
      nodes,
      relationships,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      status: "ERROR",
      message: err?.message ?? String(err),
    });
  } finally {
    await session.close();
    await driver.close();
  }
});

/* ----------------------------------
   READ GRAPH (summary)
---------------------------------- */
app.get("/graph/summary", requireToken, async (_req, res) => {
  const driver = neo4j.driver(
    NEO4J_URI,
    neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD)
  );

  const session = driver.session();

  try {
    const result = await session.run(`
      MATCH (a:Person)-[r:CANDIDATO_A]->(b:Person)
      RETURN 
        a.id AS from_id,
        a.full_name AS from_name,
        b.id AS to_id,
        b.full_name AS to_name,
        r.priority AS priority
      ORDER BY r.priority ASC
    `);

    const rows = result.records.map(r => ({
      from_id: r.get("from_id"),
      from_name: r.get("from_name"),
      to_id: r.get("to_id"),
      to_name: r.get("to_name"),
      priority: r.get("priority"),
    }));

    res.json({
      status: "OK",
      relationships: rows,
    });
  } catch (err) {
    res.status(500).json({
      status: "ERROR",
      message: err?.message ?? String(err),
    });
  } finally {
    await session.close();
    await driver.close();
  }
});

/* ----------------------------------
   START SERVER (always last)
---------------------------------- */
app.listen(Number(PORT), () => {
  console.log(`🚀 Graph service listening on port ${PORT}`);
});
