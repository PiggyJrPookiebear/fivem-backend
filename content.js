(function () {
  const CONTENT_KEY = 'spermlings_content';

  function loadContent() {
    try {
      const raw = localStorage.getItem(CONTENT_KEY);
      const data = raw ? JSON.parse(raw) : {};
      return data && typeof data === 'object' ? data : {};
    } catch {
      return {};
    }
  }

  function saveContent(data) {
    localStorage.setItem(CONTENT_KEY, JSON.stringify(data));
  }

  function applyContent(root = document) {
    const data = loadContent();
    const nodes = root.querySelectorAll('[data-content-key]');
    nodes.forEach((el) => {
      const key = el.getAttribute('data-content-key');
      if (!key) return;
      if (Object.prototype.hasOwnProperty.call(data, key) && typeof data[key] === 'string') {
        el.textContent = data[key];
      }
    });
  }

  window.SPERMLINGS_CONTENT = { applyContent, loadContent, saveContent };
})();
