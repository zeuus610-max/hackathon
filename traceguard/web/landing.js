const menuButton = document.querySelector("#menu-toggle");
const mainNav = document.querySelector(".main-nav");

menuButton.addEventListener("click", () => {
  const open = menuButton.getAttribute("aria-expanded") !== "true";
  menuButton.setAttribute("aria-expanded", String(open));
  menuButton.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
  mainNav.classList.toggle("open", open);
});

mainNav.querySelectorAll("a").forEach((link) => {
  link.addEventListener("click", () => {
    mainNav.classList.remove("open");
    menuButton.setAttribute("aria-expanded", "false");
    menuButton.setAttribute("aria-label", "Open navigation");
  });
});

const flowCopy = {
  identity: {
    title: "IDENTITY + CREDENTIAL",
    description: "Check active status, key ownership, expiry and restrictions. The case shows a broad TallyBridge key and a post-termination account sign-in.",
  },
  permission: {
    title: "PERMISSION · THIS VENDOR",
    description: "Check object-level access to this vendor and this field. A contact-sync integration should not write bank details.",
  },
  approval: {
    title: "FINANCE APPROVAL · EXACT DETAILS",
    description: "Match approval to vendor V-0412 and the exact new bank details. E19 has no approval reference for this change.",
  },
  risk: {
    title: "RISK CONTEXT · REVIEW SIGNALS",
    description: "Check exports, source host, client version and related access. BlueVault timing remains uncertain because its clock was unsynchronized.",
  },
};

document.querySelectorAll(".flow-node").forEach((node) => {
  node.addEventListener("click", () => {
    document.querySelectorAll(".flow-node").forEach((item) => {
      const active = item === node;
      item.classList.toggle("selected", active);
      item.setAttribute("aria-pressed", String(active));
    });
    const copy = flowCopy[node.dataset.node];
    document.querySelector("#selected-source").textContent = copy.title;
    document.querySelector("#node-description").textContent = copy.description;
  });
});

fetch("/api/case", { headers: { Accept: "application/json" } })
  .then((response) => {
    if (!response.ok) throw new Error(`Case API returned ${response.status}`);
    return response.json();
  })
  .then((summary) => {
    document.querySelector(".architecture-live").innerHTML = "<i></i> CASE DATA CONNECTED";
    const count = document.querySelector(".proof-strip p");
    count.setAttribute("aria-label", `${summary.evidence_total} case artifacts; ${summary.evidence_loaded} event and reference streams loaded`);
  })
  .catch(() => {
    document.querySelector(".architecture-live").innerHTML = "<i></i> CASE EXAMPLE";
  });
