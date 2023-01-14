import { defineComponent, h } from 'vue'
import { marked } from 'marked'
import xss from 'xss'

// Sections derived from MDN element categories and limited to the more
// benign categories.
// https://developer.mozilla.org/en-US/docs/Web/HTML/Element
const allowedTags = [
  // Content sectioning
  'address', 'article', 'aside', 'footer', 'header',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hgroup',
  'main', 'nav', 'section',
  // Text content
  'blockquote', 'dd', 'div', 'dl', 'dt', 'figcaption', 'figure',
  'hr', 'li', 'main', 'ol', 'p', 'pre', 'ul',
  // Inline text semantics
  'a', 'abbr', 'b', 'bdi', 'bdo', 'br', 'cite', 'code', 'data', 'dfn',
  'em', 'i', 'kbd', 'mark', 'q',
  'rb', 'rp', 'rt', 'rtc', 'ruby',
  's', 'samp', 'small', 'span', 'strong', 'sub', 'sup', 'time', 'u', 'var', 'wbr',
  // Table content
  'caption', 'col', 'colgroup', 'table', 'tbody', 'td', 'tfoot', 'th',
  'thead', 'tr',
]

const voidTags = ['img', 'br', 'hr', 'area', 'base', 'basefont', 'input', 'link', 'meta']

const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:']

function checkUrl(value: string) {
  try {
    const url = new URL(value)
    return allowedProtocols.includes(url.protocol)
  } catch (e) {
    return false
  }
}

export function sanitize(html: string) {
  const whiteList: XSS.IWhiteList = {
    ...Object.fromEntries(allowedTags.map(tag => [tag, []])),
    a: ['target', 'href', 'title', 'rel'],
  }
  const stack: string[] = []
  html = xss(html, {
    whiteList,
    stripIgnoreTag: true,
    onTag(tag, html, options) {
      if (html.endsWith('/>') || voidTags.includes(tag)) return
      if (!options.isClosing) {
        stack.push(tag)
        return
      }
      let result = ''
      while (stack.length) {
        const last = stack.pop()
        if (last === tag) {
          return result + html
        }
        result += `</${last}>`
      }
      return html.replace(/</g, '&lt;').replace(/>/g, '&gt;')
    },
    onTagAttr(tag, name, value, isWhiteAttr) {
      if (name === 'href') {
        if (!checkUrl(value)) return ''
      }
    },
  })
  while (stack.length) {
    const last = stack.pop()
    html += `</${last}>`
  }
  return html
}

export default defineComponent({
  props: {
    source: String,
    inline: Boolean,
    tag: String,
    safe: Boolean,
  },
  setup(props) {
    let html = props.inline
      ? marked.parseInline(props.source || '')
      : marked.parse(props.source || '')
    if (props.safe ?? props.inline) html = sanitize(html)
    return () => {
      const tag = props.tag || (props.inline ? 'span' : 'div')
      return h(tag, {
        class: 'markdown',
        innerHTML: html,
      })
    }
  },
})
