(root) => {
  const emoji = 'img.emoji[alt]';
  function read(node) {
    if (!node) return '';
    if (node.nodeType === Node.TEXT_NODE) {
      const whitespace = getComputedStyle(node.parentElement).whiteSpace;
      return /^(pre|pre-wrap|break-spaces)$/.test(whitespace) ? node.textContent
        : whitespace === 'pre-line' ? node.textContent.replace(/[\t\r\f ]+/g, ' ')
        : node.textContent.replace(/[\t\r\n\f ]+/g, ' ');
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return '';
    const style = getComputedStyle(node);
    if (style.display === 'none' || ['hidden', 'collapse'].includes(style.visibility)
        || ['SCRIPT', 'STYLE', 'TEMPLATE'].includes(node.tagName)) return '';
    if (node.matches(emoji)) return node.getAttribute('alt');
    if (node.tagName === 'BR') return '\n';
    if (!node.querySelector(emoji)) return node.innerText || '';
    let result = '', previousBlock = false;
    for (const child of node.childNodes) {
      const part = read(child);
      if (!part) continue;
      const display = child.nodeType === Node.ELEMENT_NODE ? getComputedStyle(child).display : '';
      const block = /^(block|flow-root|flex|grid|list-item|table|table-row)$/.test(display);
      if (result && (block || previousBlock) && !result.endsWith('\n') && !part.startsWith('\n')) result += '\n';
      result += part;
      previousBlock = block;
    }
    return result;
  }
  return read(root);
}
