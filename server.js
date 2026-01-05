app.get("/api/_debug/effects", requireAdmin, async (_req, res) => {
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
      .select("id, user_id, target_user_id, priority")
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
