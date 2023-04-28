import { defineComponent, h } from 'vue'
import { marked } from 'marked'
import * as xss from 'xss'

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
    const url = new URL(value, location.toString())
    return allowedProtocols.includes(url.protocol)
  } catch (e) {
    return false
  }
}

export function sanitize(html: string) {
  const whiteList: XSS.IWhiteList = {
    ...Object.fromEntries(allowedTags.map(tag => [tag, []])),
  }
  const stack: string[] = []
  html = xss.filterXSS(html, {
    whiteList,
    stripIgnoreTag: true,
    onTag(tag, raw, options) {
      let html: string | undefined
      if (tag === 'a' && !options.isClosing) {
        const attrs: any = {}
        xss.parseAttr(raw.slice(3), (name, value) => {
          if (name === 'href') {
            attrs[name] = checkUrl(value) ? value : '#'
          } else if (name === 'title') {
            attrs[name] = xss.escapeAttrValue(value)
          }
          return ''
        })
        attrs.rel = 'noopener noreferrer'
        attrs.target = '_blank'
        html = `<a ${Object.entries(attrs).map(([name, value]) => `${name}="${value}"`).join(' ')}>`
      }
      if (raw.endsWith('/>') || voidTags.includes(tag)) return
      if (!options.isClosing) {
        stack.push(tag)
        return html
      }
      let result = ''
      while (stack.length) {
        const last = stack.pop()
        if (last === tag) {
          return result + raw
        }
        result += `</${last}>`
      }
      return raw.replace(/</g, '&lt;').replace(/>/g, '&gt;')
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
    unsafe: Boolean,
  },
  setup(props) {
    return () => {
      let html = props.inline
        ? marked.parseInline(props.source || '')
        : marked.parse(props.source || '')
      if (!props.unsafe) html = sanitize(html)
      const tag = props.tag || (props.inline ? 'span' : 'div')
      return h(tag, {
        class: 'markdown',
        innerHTML: html,
      })
    }
  },
})
