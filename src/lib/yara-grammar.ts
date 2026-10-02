// TextMate grammar for YARA rules: Shiki doesn't bundle one, so Expressive Code
// loads it via `shiki.langs` in astro.config.ts. Use it with ```yara fences.
// Scopes are picked to get distinct colors from the github-light/dark themes.

const comments = [
  { name: 'comment.line.double-slash.yara', match: '//.*$' },
  { name: 'comment.block.yara', begin: '/\\*', end: '\\*/' },
]

export const yara = {
  name: 'yara',
  scopeName: 'source.yara',
  aliases: ['yar'],
  patterns: [
    { include: '#comments' },
    { include: '#import' },
    { include: '#rule-header' },
    { include: '#meta-section' },
    { include: '#strings-section' },
    { include: '#condition-section' },
    { name: 'punctuation.section.block.yara', match: '[{}]' },
  ],
  repository: {
    comments: { patterns: comments },

    import: {
      patterns: [
        { name: 'keyword.control.import.yara', match: '\\b(?:import|include)\\b' },
        { include: '#string' },
      ],
    },

    // [private|global] rule Name [: tag1 tag2]
    'rule-header': {
      match:
        '\\b((?:(?:private|global)\\s+)*)(rule)\\s+([A-Za-z_]\\w*)(?:\\s*(:)\\s*([A-Za-z_][\\w ]*?))?(?=\\s*(?:\\{|$))',
      captures: {
        1: { name: 'storage.modifier.yara' },
        2: { name: 'storage.type.rule.yara' },
        3: { name: 'entity.name.function.yara' },
        4: { name: 'punctuation.separator.tags.yara' },
        5: { name: 'entity.other.inherited-class.tag.yara' },
      },
    },

    // A section runs until the next section label or the rule's closing brace
    'meta-section': {
      begin: '\\b(meta)\\s*(:)',
      beginCaptures: {
        1: { name: 'keyword.other.section.yara' },
        2: { name: 'punctuation.separator.yara' },
      },
      end: '(?=\\b(?:strings|condition)\\s*:|\\})',
      patterns: [
        { include: '#comments' },
        {
          match: '\\b([A-Za-z_]\\w*)\\s*(=)',
          captures: {
            1: { name: 'entity.other.attribute-name.yara' },
            2: { name: 'keyword.operator.assignment.yara' },
          },
        },
        { include: '#string' },
        { include: '#number' },
        { name: 'constant.language.boolean.yara', match: '\\b(?:true|false)\\b' },
      ],
    },

    'strings-section': {
      begin: '\\b(strings)\\s*(:)',
      beginCaptures: {
        1: { name: 'keyword.other.section.yara' },
        2: { name: 'punctuation.separator.yara' },
      },
      end: '(?=\\b(?:meta|condition)\\s*:|\\})',
      patterns: [
        { include: '#comments' },
        { include: '#identifier' },
        { name: 'keyword.operator.assignment.yara', match: '=' },
        { include: '#string' },
        { include: '#regex' },
        { include: '#hex-string' },
        {
          name: 'storage.modifier.yara',
          match: '\\b(?:ascii|wide|nocase|fullword|private|xor|base64|base64wide)\\b',
        },
        { include: '#number' },
        { name: 'keyword.operator.range.yara', match: '-' },
      ],
    },

    'condition-section': {
      begin: '\\b(condition)\\s*(:)',
      beginCaptures: {
        1: { name: 'keyword.other.section.yara' },
        2: { name: 'punctuation.separator.yara' },
      },
      end: '(?=\\})',
      patterns: [
        { include: '#comments' },
        { include: '#string' },
        { include: '#regex' },
        { include: '#identifier' },
        { include: '#number' },
        {
          name: 'keyword.operator.word.yara',
          match:
            '\\b(?:and|or|not|at|in|of|for|matches|contains|icontains|startswith|istartswith|endswith|iendswith|iequals|defined)\\b',
        },
        {
          name: 'constant.language.yara',
          match: '\\b(?:all|any|none|them|true|false|filesize|entrypoint)\\b',
        },
        {
          name: 'support.function.yara',
          match: '\\bu?int(?:8|16|32)(?:be)?\\b',
        },
        // Module access, e.g. pe.imports(...) or math.entropy(...)
        {
          match: '\\b([a-z_]\\w*)(\\.)([A-Za-z_][\\w.]*)',
          captures: {
            1: { name: 'support.type.module.yara' },
            2: { name: 'punctuation.accessor.yara' },
            3: { name: 'support.function.yara' },
          },
        },
        {
          name: 'keyword.operator.yara',
          match: '==|!=|<=|>=|<<|>>|\\.\\.|[<>+\\-*\\\\%&|^~]',
        },
      ],
    },

    // $name, $prefix*, #count, @offset, !length
    identifier: {
      name: 'variable.name.string-identifier.yara',
      match: '\\$[A-Za-z0-9_]*\\*?|[#@!][A-Za-z_]\\w*\\*?',
    },

    string: {
      name: 'string.quoted.double.yara',
      begin: '"',
      end: '"',
      patterns: [
        {
          name: 'constant.character.escape.yara',
          match: '\\\\(?:x[0-9A-Fa-f]{2}|[nrt"\\\\])',
        },
      ],
    },

    // YARA divides with a backslash, so a slash always starts a regex (or a comment)
    regex: {
      name: 'string.regexp.yara',
      begin: '/(?![/*])',
      end: '/[is]*',
      patterns: [{ name: 'constant.character.escape.yara', match: '\\\\.' }],
    },

    number: {
      name: 'constant.numeric.yara',
      match: '\\b(?:0x[0-9A-Fa-f]+|0o[0-7]+|\\d+(?:\\.\\d+)?(?:KB|MB)?)\\b',
    },

    // { 4D 5A ?? [2-4] ( 01 | 02 ) ~00 }
    'hex-string': {
      begin: '\\{',
      end: '\\}',
      beginCaptures: { 0: { name: 'punctuation.definition.hex.begin.yara' } },
      endCaptures: { 0: { name: 'punctuation.definition.hex.end.yara' } },
      patterns: [
        ...comments,
        {
          name: 'keyword.operator.wildcard.yara',
          match: '~?(?:\\?\\?|[0-9A-Fa-f]\\?|\\?[0-9A-Fa-f])',
        },
        { name: 'constant.numeric.hex.yara', match: '~?[0-9A-Fa-f]{2}' },
        { name: 'keyword.operator.jump.yara', match: '\\[\\s*\\d*\\s*(?:-\\s*\\d*\\s*)?\\]' },
        { name: 'keyword.operator.alternation.yara', match: '[|()]' },
      ],
    },
  },
}
