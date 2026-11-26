const categories = [
  { id: "ai", file: "AI.md", title: { zh: "AI", en: "AI" } },
  { id: "forensics", file: "forensics.md", title: { zh: "取证", en: "Forensics" } },
  { id: "misc", file: "Misc.md", title: { zh: "杂项", en: "Misc" } },
  { id: "pwn", file: "pwn.md", title: { zh: "Pwn", en: "Pwn" } },
  { id: "reverse", file: "reverse.md", title: { zh: "逆向工程", en: "Reverse Engineering" } },
  { id: "web", file: "web.md", title: { zh: "Web", en: "Web" } },
];

const copy = {
  zh: {
    pageTitle: "题解 / Writeups",
    pageDescription: "按分类整理的中英文题目记录。",
    headerLabel: "题解档案",
    browse: "浏览题目",
    categories: "分类",
    topics: "题目",
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
    browse: "Browse challenges",
    categories: "Categories",
    topics: "Challenges",
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
  document.getElementById("browse-label").textContent = labels.browse;
  document.getElementById("category-label").textContent = labels.categories;
  document.getElementById("topic-label").textContent = labels.topics;
  document.getElementById("back-to-top").textContent = labels.backToTop;
  document.getElementById("load-status").textContent = labels.loading;

  const languageLink = document.getElementById("language-link");
  const nextUrl = new URL(window.location.href);
  nextUrl.searchParams.set("lang", language === "zh" ? "en" : "zh");
  languageLink.href = `${nextUrl.pathname}${nextUrl.search}${nextUrl.hash}`;
  languageLink.textContent = labels.languageLink;
  languageLink.lang = language === "zh" ? "en" : "zh-CN";
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
  const topicNav = document.getElementById("topic-nav");

  categoryNav.innerHTML = `<ul>${categories.map((category) => `
    <li><a href="#category-${category.id}">${escapeHtml(category.title[language])}</a></li>
  `).join("")}</ul>`;

  topicNav.innerHTML = `<ul>${renderedSections.flatMap((section) => {
    const headings = [...section.querySelectorAll(".writeup-body h2, .writeup-body h3")];
    return headings.map((heading) => `
      <li class="level-${heading.tagName.slice(1)}"><a href="#${heading.id}">${escapeHtml(heading.textContent)}</a></li>
    `);
  }).join("")}</ul>`;
}

function observeSections() {
  if (!("IntersectionObserver" in window)) return;
  const links = [...document.querySelectorAll("#category-nav a, #topic-nav a")];
  const linkById = new Map(links.map((link) => [decodeURIComponent(link.hash.slice(1)), link]));
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      for (const link of links) link.classList.remove("active");
      linkById.get(entry.target.id)?.classList.add("active");
    }
  }, { rootMargin: "-18% 0px -70% 0px" });

  document.querySelectorAll(".writeup-section, .writeup-body h2, .writeup-body h3").forEach((node) => observer.observe(node));
}

async function start() {
  const language = currentLanguage();
  configureLabels(language);

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

    const sidebar = document.querySelector(".sidebar-details");
    if (window.matchMedia("(max-width: 800px)").matches) sidebar.open = false;
  } catch (error) {
    const status = document.getElementById("load-status");
    status.classList.add("error");
    status.textContent = copy[language].loadError;
    console.error(error);
  }
}

document.addEventListener("DOMContentLoaded", start);
