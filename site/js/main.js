/* =========================================================
   Federal Data Science Learning Handbook — Main JS
   Navigation, dark mode, smooth scroll, mobile menu,
   table of contents, code copy buttons
   ========================================================= */

'use strict';

// ---- Dark Mode ----
// UX-021: Theme initialization moved to inline <script> in <head> to prevent
// flash of wrong theme on load. This IIFE is intentionally removed from here.

function toggleTheme() {
  var current = document.documentElement.getAttribute('data-theme');
  var next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  updateThemeIcon(next);
  // UX-016: Announce theme change to screen readers via aria-live region
  var statusEl = document.getElementById('theme-status');
  if (statusEl) {
    statusEl.textContent = next === 'dark' ? 'Dark mode enabled' : 'Light mode enabled';
  }
}

function updateThemeIcon(theme) {
  var btn = document.getElementById('theme-toggle');
  if (!btn) return;
  var sunIcon = btn.querySelector('.icon-sun');
  var moonIcon = btn.querySelector('.icon-moon');
  if (sunIcon && moonIcon) {
    if (theme === 'dark') {
      sunIcon.style.display = 'block';
      moonIcon.style.display = 'none';
    } else {
      sunIcon.style.display = 'none';
      moonIcon.style.display = 'block';
    }
  }
}

// ---- Mobile Sidebar ----

function initMobileMenu() {
  var btn = document.getElementById('mobile-menu-btn');
  var sidebar = document.querySelector('.sidebar');
  var overlay = document.querySelector('.sidebar-overlay');

  if (!btn || !sidebar) return;

  btn.addEventListener('click', function() {
    var isOpen = sidebar.classList.contains('open');
    sidebar.classList.toggle('open', !isOpen);
    if (overlay) overlay.classList.toggle('active', !isOpen);
    btn.setAttribute('aria-expanded', String(!isOpen));
    document.body.style.overflow = isOpen ? '' : 'hidden';
  });

  if (overlay) {
    overlay.addEventListener('click', closeSidebar);
  }

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeSidebar();
  });

  function closeSidebar() {
    sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
    btn.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
  }

  // Close sidebar on nav link click (mobile)
  sidebar.querySelectorAll('a').forEach(function(link) {
    link.addEventListener('click', function() {
      if (window.innerWidth <= 900) closeSidebar();
    });
  });
}

// ---- Active Navigation State ----

function initActiveNav() {
  var currentPath = window.location.pathname;
  var allLinks = document.querySelectorAll('.sidebar-nav a, .nav-links a');

  allLinks.forEach(function(link) {
    var linkPath = link.getAttribute('href');
    if (!linkPath) return;

    var normalizedCurrent = currentPath.replace(/\/index\.html$/, '/');
    var normalizedLink = linkPath.replace(/\/index\.html$/, '/');

    if (normalizedCurrent.endsWith(normalizedLink) || linkPath === currentPath) {
      link.classList.add('active');
    }
  });
}

// ---- Table of Contents / Scroll Spy ----

function initScrollSpy() {
  var tocLinks = document.querySelectorAll('.toc-list a');
  if (!tocLinks.length) return;

  var headings = Array.from(document.querySelectorAll('.prose h2, .prose h3, .prose h4'));
  if (!headings.length) return;

  var ticking = false;
  var NAV_HEIGHT = 80;

  function updateActiveToc() {
    var scrollPos = window.scrollY + NAV_HEIGHT + 20;
    var active = headings[0];

    for (var i = 0; i < headings.length; i++) {
      if (headings[i].offsetTop <= scrollPos) {
        active = headings[i];
      } else {
        break;
      }
    }

    tocLinks.forEach(function(link) {
      var href = link.getAttribute('href');
      var targetId = href && href.startsWith('#') ? href.slice(1) : null;
      link.classList.toggle('active', active && targetId === active.id);
    });

    ticking = false;
  }

  window.addEventListener('scroll', function() {
    if (!ticking) {
      requestAnimationFrame(updateActiveToc);
      ticking = true;
    }
  }, { passive: true });

  updateActiveToc();
}

// ---- Auto-generate Table of Contents ----

function buildToc() {
  var tocContainer = document.getElementById('toc-list');
  if (!tocContainer) return;

  var prose = document.querySelector('.prose');
  if (!prose) return;

  var headings = prose.querySelectorAll('h2, h3');
  if (!headings.length) return;

  var fragment = document.createDocumentFragment();

  headings.forEach(function(heading, i) {
    if (!heading.id) {
      heading.id = 'section-' + slugify(heading.textContent) + '-' + i;
    }

    var li = document.createElement('li');
    li.className = heading.tagName === 'H3' ? 'toc-h3' : 'toc-h2';

    var a = document.createElement('a');
    a.href = '#' + heading.id;
    a.textContent = heading.textContent;

    li.appendChild(a);
    fragment.appendChild(li);
  });

  tocContainer.textContent = '';
  tocContainer.appendChild(fragment);
}

function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// ---- Code Copy Buttons ----

function makeCopySvg() {
  var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', '13');
  svg.setAttribute('height', '13');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  var rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  rect.setAttribute('x', '9'); rect.setAttribute('y', '9');
  rect.setAttribute('width', '13'); rect.setAttribute('height', '13');
  rect.setAttribute('rx', '2'); rect.setAttribute('ry', '2');
  var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1');
  svg.appendChild(rect);
  svg.appendChild(path);
  return svg;
}

function makeCheckSvg() {
  var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', '13');
  svg.setAttribute('height', '13');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  var poly = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
  poly.setAttribute('points', '20 6 9 17 4 12');
  svg.appendChild(poly);
  return svg;
}

function attachCopyHandler(btn, getCode) {
  btn.addEventListener('click', function() {
    var text = getCode();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function() {
        showCopied(btn);
      }).catch(function() {
        fallbackCopy(text);
        showCopied(btn);
      });
    } else {
      fallbackCopy(text);
      showCopied(btn);
    }
  });
}

function showCopied(btn) {
  btn.classList.add('copied');
  btn.textContent = '';
  btn.appendChild(makeCheckSvg());
  btn.appendChild(document.createTextNode(' Copied!'));
  setTimeout(function() {
    btn.classList.remove('copied');
    btn.textContent = '';
    btn.appendChild(makeCopySvg());
    btn.appendChild(document.createTextNode(' Copy'));
  }, 2000);
}

function fallbackCopy(text) {
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
}

function initCodeCopy() {
  // Handle .code-block-wrapper elements (with header)
  document.querySelectorAll('.code-block-wrapper').forEach(function(wrapper) {
    var btn = wrapper.querySelector('.code-copy-btn');
    var pre = wrapper.querySelector('pre');
    if (!btn || !pre) return;

    attachCopyHandler(btn, function() {
      var code = pre.querySelector('code') || pre;
      return code.textContent || '';
    });
  });

  // Add floating copy buttons to plain prose pre blocks
  document.querySelectorAll('.prose pre').forEach(function(pre) {
    // Skip if already inside a code-block-wrapper
    if (pre.closest('.code-block-wrapper')) return;
    // Skip if already wrapped
    if (pre.parentElement.getAttribute('data-copy-wrapper')) return;

    var container = document.createElement('div');
    container.style.position = 'relative';
    container.setAttribute('data-copy-wrapper', '1');
    pre.parentNode.insertBefore(container, pre);
    container.appendChild(pre);

    var btn = document.createElement('button');
    btn.className = 'code-copy-btn floating';
    btn.setAttribute('aria-label', 'Copy code');
    btn.appendChild(makeCopySvg());
    btn.appendChild(document.createTextNode(' Copy'));

    // UX-020: Use high-contrast colors for floating copy button (was ~2.1:1, now ~6:1)
    Object.assign(btn.style, {
      position: 'absolute',
      top: '0.5rem',
      right: '0.5rem',
      display: 'flex',
      alignItems: 'center',
      gap: '0.3rem',
      padding: '0.25rem 0.625rem',
      fontSize: '0.7rem',
      fontWeight: '500',
      color: 'rgba(255,255,255,0.85)',
      background: 'rgba(27,42,74,0.85)',
      border: '1px solid rgba(255,255,255,0.15)',
      borderRadius: '4px',
      cursor: 'pointer',
      transition: 'all 0.15s',
      fontFamily: 'inherit',
    });

    btn.addEventListener('mouseenter', function() {
      btn.style.color = '#FFFFFF';
      btn.style.background = 'rgba(27,42,74,0.98)';
    });
    btn.addEventListener('mouseleave', function() {
      if (!btn.classList.contains('copied')) {
        btn.style.color = 'rgba(255,255,255,0.85)';
        btn.style.background = 'rgba(27,42,74,0.85)';
      }
    });

    container.appendChild(btn);

    attachCopyHandler(btn, function() {
      var code = pre.querySelector('code') || pre;
      return code.textContent || '';
    });
  });
}

// ---- Smooth Scroll for Anchor Links ----

function initSmoothScroll() {
  document.addEventListener('click', function(e) {
    var link = e.target.closest('a[href^="#"]');
    if (!link) return;

    var href = link.getAttribute('href');
    if (href === '#') return;

    var target = document.querySelector(href);
    if (!target) return;

    e.preventDefault();

    var navHeight = 80;
    var top = target.getBoundingClientRect().top + window.scrollY - navHeight - 16;
    window.scrollTo({ top: top, behavior: 'smooth' });

    history.pushState(null, '', href);
  });
}

// ---- Reading Progress Bar ----

function initProgressBar() {
  var prose = document.querySelector('.prose');
  if (!prose) return;

  var bar = document.createElement('div');
  Object.assign(bar.style, {
    position: 'fixed',
    top: '64px',
    left: '0',
    height: '2px',
    background: 'var(--advana-gold)',
    zIndex: '200',
    width: '0%',
    transition: 'width 0.1s linear',
    pointerEvents: 'none',
  });
  document.body.appendChild(bar);

  var ticking = false;
  window.addEventListener('scroll', function() {
    if (!ticking) {
      requestAnimationFrame(function() {
        var total = document.documentElement.scrollHeight - window.innerHeight;
        var progress = total > 0 ? (window.scrollY / total) * 100 : 0;
        bar.style.width = Math.min(progress, 100) + '%';
        ticking = false;
      });
      ticking = true;
    }
  }, { passive: true });
}

// ---- Mermaid diagram wrapper enhancement ----

function wrapMermaidDiagrams() {
  document.querySelectorAll('.mermaid').forEach(function(el) {
    if (el.parentElement.classList.contains('mermaid-wrapper')) return;
    var wrapper = document.createElement('div');
    wrapper.className = 'mermaid-wrapper';
    el.parentNode.insertBefore(wrapper, el);
    wrapper.appendChild(el);
  });
}

// ---- Nav scroll behavior ----

function initNavScroll() {
  var nav = document.querySelector('.site-nav');
  if (!nav) return;

  var ticking = false;

  window.addEventListener('scroll', function() {
    if (!ticking) {
      requestAnimationFrame(function() {
        if (window.scrollY > 10) {
          nav.style.boxShadow = '0 1px 12px rgba(0,0,0,0.08)';
        } else {
          nav.style.boxShadow = 'none';
        }
        ticking = false;
      });
      ticking = true;
    }
  }, { passive: true });
}

// ---- Initialize everything ----

document.addEventListener('DOMContentLoaded', function() {
  var currentTheme = document.documentElement.getAttribute('data-theme');
  updateThemeIcon(currentTheme);

  var themeBtn = document.getElementById('theme-toggle');
  if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

  initMobileMenu();
  initActiveNav();
  buildToc();
  initScrollSpy();
  initCodeCopy();
  initSmoothScroll();
  initProgressBar();
  setTimeout(wrapMermaidDiagrams, 600);
  initNavScroll();

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
    if (!localStorage.getItem('theme')) {
      var theme = e.matches ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', theme);
      updateThemeIcon(theme);
    }
  });
});
