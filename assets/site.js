const categories = [
  { id: "web", file: "web.md", title: { zh: "Web", en: "Web" } },
  { id: "misc", file: "Misc.md", title: { zh: "Misc", en: "Misc" } },
  { id: "pwn", file: "pwn.md", title: { zh: "Pwn", en: "Pwn" } },
  { id: "reverse", file: "reverse.md", title: { zh: "Reverse", en: "Reverse" } },
  { id: "forensics", file: "forensics.md", title: { zh: "Forensics", en: "Forensics" } },
  { id: "ai", file: "AI.md", title: { zh: "AI", en: "AI" } },
];

const copy = {
  zh: {
    pageTitle: "题解 / Writeups",
    pageDescription: "按分类整理的中英文题目记录。",
    headerLabel: "题解档案",
    navLabel: "题目分类导航",
    toggleNav: "打开侧边导航",
    closeNav: "关闭侧边导航",
    languageLink: "English",
    loadError: "题目内容载入失败，请通过本地 HTTP 服务或 GitHub Pages 打开此页面。",
    loading: "正在载入题目…",
    backToTop: "回到顶部",
    section: "分类",
  },
  en: {
    pageTitle: "Writeups",
    pageDescription: "Challenge notes, organized by category.",
    headerLabel: "Challenge archive",
    navLabel: "Challenge navigation",
    toggleNav: "Open navigation",
    closeNav: "Close navigation",
    languageLink: "中文",
    loadError: "The writeups could not be loaded. Open this page through a local HTTP server or GitHub Pages.",
    loading: "Loading writeups…",
    backToTop: "Back to top",
    section: "Category",
  },
};

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
}[char]));

const slugify = (value) => value
  .toLocaleLowerCase()
  .trim()
  .replace(/[^\p{L}\p{N}]+/gu, "-")
  .replace(/^-|-$/g, "");

function currentLanguage() {
  return new URLSearchParams(window.location.search).get("lang") === "en" ? "en" : "zh";
}

function configureLabels(language) {
  const labels = copy[language];
  document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
  document.title = language === "zh" ? "Curtin CTF4 2026 题解" : "Curtin CTF4 2026 Writeups";
  document.getElementById("page-title").textContent = labels.pageTitle;
  document.getElementById("page-description").textContent = labels.pageDescription;
  document.getElementById("header-label").textContent = labels.headerLabel;
  document.getElementById("category-label").textContent = language === "zh" ? "分类目录" : "Categories";
  document.getElementById("site-sidebar").setAttribute("aria-label", labels.navLabel);
  document.getElementById("category-nav").setAttribute("aria-label", labels.navLabel);
  const navToggle = document.getElementById("nav-toggle");
  navToggle.setAttribute("aria-label", labels.toggleNav);
  navToggle.title = labels.toggleNav;
  document.getElementById("sidebar-scrim").setAttribute("aria-label", labels.closeNav);
  document.getElementById("back-to-top").textContent = labels.backToTop;
  document.getElementById("load-status").textContent = labels.loading;

  const languageLink = document.getElementById("language-link");
  const nextUrl = new URL(window.location.href);
  nextUrl.searchParams.set("lang", language === "zh" ? "en" : "zh");
  languageLink.href = `${nextUrl.pathname}${nextUrl.search}${nextUrl.hash}`;
  languageLink.textContent = labels.languageLink;
  languageLink.lang = language === "zh" ? "en" : "zh-CN";
  languageLink.addEventListener("click", (event) => {
    event.preventDefault();
    const target = new URL(window.location.href);
    target.searchParams.set("lang", language === "zh" ? "en" : "zh");
    window.location.assign(target.href);
  });
  window.addEventListener("hashchange", () => {
    const target = new URL(window.location.href);
    target.searchParams.set("lang", language === "zh" ? "en" : "zh");
    languageLink.href = `${target.pathname}${target.search}${target.hash}`;
  });
}

function markdownRenderer(category, sourceUrl) {
  const renderer = new window.marked.Renderer();
  renderer.heading = ({ tokens, depth }) => {
    if (depth === 1) return "";
    const text = tokens.map((token) => token.text ?? token.raw ?? "").join("");
    const id = `${category.id}-${slugify(text)}`;
    return `<h${depth} id="${escapeHtml(id)}">${escapeHtml(text)}</h${depth}>`;
  };
  renderer.image = ({ href, title, text }) => {
    const src = new URL(href, sourceUrl).href;
    const titleAttribute = title ? ` title="${escapeHtml(title)}"` : "";
    return `<img src="${escapeHtml(src)}" alt="${escapeHtml(text)}"${titleAttribute} loading="lazy">`;
  };
  return renderer;
}

async function loadCategory(category, language, position) {
  const filename = language === "en" ? `docs/en/${category.file}` : `docs/${category.file}`;
  const sourceUrl = new URL(filename, document.baseURI);
  const response = await fetch(sourceUrl);
  if (!response.ok) throw new Error(`${filename}: HTTP ${response.status}`);

  const markdown = await response.text();
  const title = category.title[language];
  const renderer = markdownRenderer(category, sourceUrl);
  const article = document.createElement("section");
  article.className = "writeup-section";
  article.id = `category-${category.id}`;
  article.setAttribute("aria-labelledby", `${category.id}-heading`);
  article.innerHTML = `
    <h2 class="category-heading" id="${category.id}-heading">
      <span>${copy[language].section} ${String(position + 1).padStart(2, "0")}</span>
      ${escapeHtml(title)}
    </h2>
    <div class="writeup-body">${window.marked.parse(markdown, { gfm: true, renderer })}</div>
  `;
  return article;
}

function buildNavigation(language, renderedSections) {
  const categoryNav = document.getElementById("category-nav");
  const nodes = renderedSections.map((section, index) => {
    const category = categories[index];
    const headings = [...section.querySelectorAll(".writeup-body h2, .writeup-body h3")];
    const roots = [];
    const stack = [{ depth: 1, children: roots }];

    for (const heading of headings) {
      const depth = Number(heading.tagName.slice(1));
      const node = { id: heading.id, title: heading.textContent, depth, children: [] };
      while (stack.at(-1).depth >= depth) stack.pop();
      stack.at(-1).children.push(node);
      stack.push({ depth, children: node.children });
    }

    const renderTopics = (items) => items.length ? `<ul>${items.map((item) => `
      <li class="level-${item.depth}">
        <a href="#${escapeHtml(item.id)}">${escapeHtml(item.title)}</a>
        ${renderTopics(item.children)}
      </li>
    `).join("")}</ul>` : "";

    return `
      <li class="category-item">
        <a class="category-link" href="#category-${category.id}">${escapeHtml(category.title[language])}</a>
        ${renderTopics(roots)}
      </li>
    `;
  });

  categoryNav.innerHTML = `<ul class="category-tree">${nodes.join("")}</ul>`;
}

function observeSections() {
  if (!("IntersectionObserver" in window)) return;
  const links = [...document.querySelectorAll("#category-nav a")];
  const linkById = new Map(links.map((link) => [decodeURIComponent(link.hash.slice(1)), link]));
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      for (const link of links) {
        link.classList.remove("active");
        link.removeAttribute("aria-current");
      }
      const activeLink = linkById.get(entry.target.id);
      activeLink?.classList.add("active");
      activeLink?.setAttribute("aria-current", "location");
    }
  }, { rootMargin: "-18% 0px -70% 0px" });

  document.querySelectorAll(".writeup-section, .writeup-body h2, .writeup-body h3").forEach((node) => observer.observe(node));
}

function configureSidebar() {
  const sidebar = document.getElementById("site-sidebar");
  const toggle = document.getElementById("nav-toggle");
  const scrim = document.getElementById("sidebar-scrim");
  const narrowViewport = window.matchMedia("(max-width: 600px)");

  const setOpen = (open) => {
    sidebar.classList.toggle("is-open", open);
    scrim.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
  };

  toggle.addEventListener("click", () => setOpen(toggle.getAttribute("aria-expanded") !== "true"));
  scrim.addEventListener("click", () => setOpen(false));
  sidebar.addEventListener("click", (event) => {
    if (narrowViewport.matches && event.target.closest("a")) setOpen(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setOpen(false);
  });
  narrowViewport.addEventListener("change", (event) => {
    if (!event.matches) setOpen(false);
  });
}

async function start() {
  const language = currentLanguage();
  configureLabels(language);
  configureSidebar();

  if (!window.marked) {
    document.getElementById("load-status").classList.add("error");
    document.getElementById("load-status").textContent = copy[language].loadError;
    return;
  }

  try {
    const sections = await Promise.all(categories.map((category, index) => loadCategory(category, language, index)));
    const content = document.getElementById("writeup-content");
    content.replaceChildren(...sections);
    buildNavigation(language, sections);
    document.getElementById("load-status").remove();
    observeSections();
  } catch (error) {
    const status = document.getElementById("load-status");
    status.classList.add("error");
    status.textContent = copy[language].loadError;
    console.error(error);
  }
}

document.addEventListener("DOMContentLoaded", start);
