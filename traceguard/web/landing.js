(() => {
  const slides = [...document.querySelectorAll(".slide")];
  const navItems = [...document.querySelectorAll(".nav-item")];
  const currentLabel = document.querySelector("#slide-current");
  const progress = document.querySelector("#progress-fill");
  const previous = document.querySelector("#prev-slide");
  const next = document.querySelector("#next-slide");
  let current = 0;

  function showSlide(index) {
    current = (index + slides.length) % slides.length;
    slides.forEach((slide, i) => {
      const active = i === current;
      slide.classList.toggle("is-current", active);
      slide.setAttribute("aria-hidden", String(!active));
    });
    navItems.forEach((item, i) => {
      const active = i === current;
      item.classList.toggle("is-active", active);
      item.setAttribute("aria-current", active ? "step" : "false");
    });
    currentLabel.textContent = String(current + 1).padStart(2, "0");
    progress.style.width = `${((current + 1) / slides.length) * 100}%`;
    history.replaceState(null, "", `#slide-${current + 1}`);
  }

  navItems.forEach((item) => item.addEventListener("click", () => showSlide(Number(item.dataset.go))));
  document.querySelectorAll("[data-go]").forEach((button) => {
    if (!button.classList.contains("nav-item")) {
      button.addEventListener("click", () => showSlide(Number(button.dataset.go)));
    }
  });
  previous.addEventListener("click", () => showSlide(current - 1));
  next.addEventListener("click", () => showSlide(current + 1));
  document.addEventListener("keydown", (event) => {
    if (["ArrowRight", "PageDown", " "].includes(event.key)) {
      event.preventDefault();
      showSlide(current + 1);
    } else if (["ArrowLeft", "PageUp"].includes(event.key)) {
      event.preventDefault();
      showSlide(current - 1);
    } else if (event.key === "Home") {
      showSlide(0);
    } else if (event.key === "End") {
      showSlide(slides.length - 1);
    }
  });

  const initial = Number(location.hash.match(/slide-(\d)/)?.[1]);
  showSlide(Number.isInteger(initial) && initial > 0 ? initial - 1 : 0);

  const evaluate = document.querySelector("#evaluate-request");
  const result = document.querySelector(".gate-result");
  evaluate.addEventListener("click", () => {
    result.classList.add("is-blocked");
    document.querySelector("#decision-chip").textContent = "HOLD";
    document.querySelector("#decision-symbol").textContent = "!";
    document.querySelector("#decision-title").textContent = "Change held for Finance";
    document.querySelector("#decision-copy").textContent = "The bank update is stopped before commit because permission and matching approval checks fail.";
    document.querySelector("#decision-action-label").textContent = "REQUEST-TIME DECISION";
    document.querySelector("#decision-action").textContent = "Hold write · Alert Finance · Preserve evidence";
    evaluate.innerHTML = "Request held safely <span aria-hidden=\"true\">✓</span>";
    evaluate.disabled = true;
    evaluate.setAttribute("aria-label", "Simulation complete. The request is held.");
  });
})();
