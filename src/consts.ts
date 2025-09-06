import type { IconMap, SocialLink, Site } from '@/types'

export const SITE: Site = {
  title: "AviaB's Blog", 
  description:
    '',
  href: 'https://astro-erudite.vercel.app',
  author: 'AviaB',
  locale: 'en-US',
  featuredPostCount: 2,
  postsPerPage: 3,
}

export const NAV_LINKS: SocialLink[] = [
  {
    href: '/blog',
    label: 'blog',
  },
  {
    href: '/authors',
    label: 'authors',
  },
  {
    href: '/tags',
    label: 'Tags',
  },
  {
    href: '/about',
    label: 'about',
  }
]

export const SOCIAL_LINKS: SocialLink[] = [
  {
    href: 'https://github.com/AviaB1',
    label: 'GitHub',
  },
  {
    href: 'https://www.linkedin.com/in/aviabarazani',
    label: 'LinkedIn',
  },
  {
    href: 'mailto:aviabar321@gmail.com',
    label: 'Email',
  },
  {
    href: '/rss.xml',
    label: 'RSS',
  },
]

export const ICON_MAP: IconMap = {
  Website: 'lucide:globe',
  GitHub: 'lucide:github',
  LinkedIn: 'lucide:linkedin',
  Twitter: 'lucide:twitter',
  Email: 'lucide:mail',
  RSS: 'lucide:rss',
}
