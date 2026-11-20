(() => {
  const dot = document.querySelector("#service-dot");
  const state = document.querySelector("#service-state");
  const gate = document.querySelector("#gate-state");
  const provider = document.querySelector("#provider-name");
  const description = document.querySelector("#provider-description");

  fetch("/api/health", { cache: "no-store" })
    .then(response => {
      if (!response.ok) throw new Error("service unavailable");
      return response.json();
    })
    .then(health => {
      const status = health.request_gate || {};
      dot.classList.toggle("online", health.status === "ok");
      state.textContent = health.status === "ok" ? "Orbit service online" : "Orbit service needs attention";
      if (gate) gate.textContent = status.can_forward ? "ACTIVE" : status.configured ? "HOLDING" : "OFFLINE";
      provider.textContent = status.provider === "zoho_books_india" ? "Zoho Books India" : status.provider || "Finance provider";
      description.textContent = status.can_forward
        ? "Vendor bank updates pass through Orbit after caller authorization, vendor-scope checks, and independent approval of the exact details."
        : "The write path stays closed until provider and gate settings are complete.";
    })
    .catch(() => {
      if (location.protocol === "file:") {
        state.textContent = "Open over HTTP for live status";
        if (gate) gate.textContent = "SERVER REQUIRED";
        provider.textContent = "Zoho Books India";
        description.textContent = "This file preview cannot reach Orbit’s API. Open http://127.0.0.1:8000/ to view live protection status.";
        return;
      }
      state.textContent = "Orbit service unavailable";
      if (gate) gate.textContent = "OFFLINE";
      provider.textContent = "Finance provider";
      description.textContent = "Start the Orbit service to restore live protection status.";
    });
})();
