/* =========================================================
   Mermaid Diagram Initialization
   Federal Data Science Learning Handbook
   ========================================================= */

'use strict';

(function() {
  function getTheme() {
    var t = document.documentElement.getAttribute('data-theme');
    return t === 'dark' ? 'dark' : 'default';
  }

  function initMermaid() {
    if (typeof mermaid === 'undefined') return;

    var isDark = getTheme() === 'dark';

    mermaid.initialize({
      startOnLoad: false,
      theme: isDark ? 'dark' : 'neutral',
      themeVariables: isDark ? {
        primaryColor: '#1B2A4A',
        primaryTextColor: '#CDD3DE',
        primaryBorderColor: '#2E3649',
        lineColor: '#5BA3C9',
        secondaryColor: '#161B26',
        tertiaryColor: '#1C2333',
        background: '#0F1117',
        mainBkg: '#1C2333',
        nodeBorder: '#2E3649',
        clusterBkg: '#161B26',
        titleColor: '#E8E6DF',
        edgeLabelBackground: '#1C2333',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", sans-serif',
        fontSize: '14px',
      } : {
        primaryColor: '#1B2A4A',
        primaryTextColor: '#FFFFFF',
        primaryBorderColor: '#003B5C',
        lineColor: '#003B5C',
        secondaryColor: '#F4F3EF',
        tertiaryColor: '#FFFFFF',
        background: '#FAFAF8',
        mainBkg: '#EEF2F7',
        nodeBorder: '#1B2A4A',
        clusterBkg: '#F4F3EF',
        titleColor: '#1A1A1A',
        edgeLabelBackground: '#F4F3EF',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", sans-serif',
        fontSize: '14px',
      },
      flowchart: {
        curve: 'cardinal',
        padding: 20,
        htmlLabels: true,
        useMaxWidth: true,
      },
      sequence: {
        diagramMarginX: 50,
        diagramMarginY: 10,
        actorMargin: 50,
        width: 150,
        height: 65,
        boxMargin: 10,
        boxTextMargin: 5,
        noteMargin: 10,
        messageMargin: 35,
        mirrorActors: true,
        useMaxWidth: true,
      },
      gantt: {
        titleTopMargin: 25,
        barHeight: 20,
        barGap: 4,
        topPadding: 50,
        leftPadding: 75,
        gridLineStartPadding: 35,
        fontSize: 11,
        fontFamily: 'inherit',
        numberSectionStyles: 4,
        axisFormat: '%Y-%m-%d',
        useMaxWidth: true,
      },
      er: {
        diagramPadding: 20,
        layoutDirection: 'TB',
        minEntityWidth: 100,
        minEntityHeight: 75,
        entityPadding: 15,
        stroke: 'gray',
        fill: 'honeydew',
        fontSize: 12,
        useMaxWidth: true,
      },
      securityLevel: 'strict',
    });

    // Render all mermaid elements
    var diagrams = document.querySelectorAll('.mermaid');
    if (diagrams.length === 0) return;

    mermaid.run({ nodes: diagrams }).catch(function(err) {
      console.warn('Mermaid render error:', err);
    });
  }

  // Wait for DOM to be ready, then init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initMermaid);
  } else {
    initMermaid();
  }

  // Re-render on theme change
  var observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {
      if (mutation.attributeName === 'data-theme') {
        // Re-initialize with new theme
        setTimeout(function() {
          document.querySelectorAll('.mermaid').forEach(function(el) {
            // Reset rendered state so mermaid will re-render
            delete el.dataset.processed;
            el.removeAttribute('data-processed');
          });
          initMermaid();
        }, 50);
      }
    });
  });

  observer.observe(document.documentElement, { attributes: true });

})();
