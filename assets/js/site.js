const NAV_ITEMS = [
  { href: "index.html", label: "Home", color: "orange", dot: "green" },
  { href: "blog.html", label: "Blog", color: "green", dot: "red" },
  { href: "resume.html", label: "Resume", color: "red", dot: "green" },
  { href: "photography.html", label: "Photos", color: "orange", dot: "red" },
  { href: "projects.html", label: "Project", color: "blue", dot: "blue" },
];

function currentPageName() {
  const file = location.pathname.split("/").pop() || "index.html";
  return file;
}

function renderShell(active = currentPageName()) {
  const nav = document.querySelector("[data-nav]");
  if (nav) {
    const pendingGlow = sessionStorage.getItem("navGlow");
    sessionStorage.removeItem("navGlow");
    nav.innerHTML = NAV_ITEMS.map((item) => {
      const isActive = active === item.href || (active === "" && item.href === "index.html");
      const shouldGlow = pendingGlow === item.href;
      return `<a href="${item.href}" class="nav-${item.color} dot-${item.dot}${isActive ? " active" : ""}${shouldGlow ? " nav-glow" : ""}" data-nav-target="${item.href}">${item.label}</a>`;
    }).join("");

    nav.querySelectorAll("a[data-nav-target]").forEach((link) => {
      link.addEventListener("click", () => {
        link.classList.remove("nav-glow");
        void link.offsetWidth;
        link.classList.add("nav-glow");
        sessionStorage.setItem("navGlow", link.dataset.navTarget);
      });
    });
  }

  const year = document.querySelector("[data-year]");
  if (year) year.textContent = new Date().getFullYear();
}

function magneticCards(selector = "[data-tilt]") {
  document.querySelectorAll(selector).forEach((card) => {
    card.addEventListener("pointermove", (event) => {
      const rect = card.getBoundingClientRect();
      const x = (event.clientX - rect.left) / rect.width - 0.5;
      const y = (event.clientY - rect.top) / rect.height - 0.5;
      card.style.transform = `translateY(-6px) rotateX(${y * -4}deg) rotateY(${x * 5}deg)`;
    });
    card.addEventListener("pointerleave", () => {
      card.style.transform = "";
    });
  });
}

function randomAccent() {
  const colors = ["var(--red)", "var(--green)", "var(--orange)", "var(--gray)"];
  document.documentElement.style.setProperty("--play-accent", colors[Math.floor(Math.random() * colors.length)]);
}

function setupPageTransitions() {
  document.body.classList.add("page-loaded");
  document.querySelectorAll('a[href]').forEach((link) => {
    const href = link.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('http') || link.target === '_blank') return;
    link.addEventListener('click', (event) => {
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      document.body.classList.add('page-leaving');
      setTimeout(() => { window.location.href = href; }, 85);
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  renderShell();
  magneticCards();
  randomAccent();
  setupPageTransitions();
});





