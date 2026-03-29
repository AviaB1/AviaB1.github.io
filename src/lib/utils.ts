import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

const dateFormatter = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'long',
  day: 'numeric',
})

export function formatDate(date: Date) {
  return dateFormatter.format(date)
}

export function calculateWordCount(
  text: string | null | undefined,
): number {
  if (!text) return 0
  // Strip frontmatter, code blocks, HTML tags, MDX imports, and JSX expressions
  const cleaned = text
    .replace(/---[\s\S]*?---/g, '')                          // frontmatter
    .replace(/```[\s\S]*?```/g, '')                          // code blocks
    .replace(/<[^>]+>/g, '')                                 // HTML tags
    .replace(/import\s+.*?from\s+['"].*?['"]/g, '')         // MDX imports
    .replace(/\{[^}]*\}/g, '')                               // JSX expressions
  return cleaned.split(/\s+/).filter(Boolean).length
}

/** @deprecated Use calculateWordCount instead */
export const calculateWordCountFromHtml = calculateWordCount

export function readingTime(wordCount: number): string {
  const readingTimeMinutes = Math.max(1, Math.round(wordCount / 200))
  return `${readingTimeMinutes} min read`
}

export function getHeadingMargin(depth: number): string {
  const margins: Record<number, string> = {
    3: 'ml-4',
    4: 'ml-8',
    5: 'ml-12',
    6: 'ml-16',
  }
  return margins[depth] || ''
}
