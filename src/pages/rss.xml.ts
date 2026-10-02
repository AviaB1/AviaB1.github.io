import { SITE } from '@/consts'
import rss from '@astrojs/rss'
import type { APIContext } from 'astro'
import { getAllPosts } from '@/lib/data-utils'

export async function GET(context: APIContext) {
  try {
    const posts = await getAllPosts()
    const site = context.site ?? SITE.href

    return rss({
      title: SITE.title,
      description: SITE.description,
      site,
      xmlns: {
        atom: 'http://www.w3.org/2005/Atom',
        dc: 'http://purl.org/dc/elements/1.1/',
      },
      customData: `<language>en-us</language><atom:link href="${new URL('rss.xml', site)}" rel="self" type="application/rss+xml"/>`,
      items: posts.map((post) => ({
        title: post.data.title,
        description: post.data.description,
        pubDate: post.data.date,
        link: `/blog/${post.id}/`,
        categories: post.data.tags ?? [],
        // RSS 2.0 <author> must be an email address, so use dc:creator
        customData: '<dc:creator>Avia Barazani</dc:creator>',
      })),
    })
  } catch (error) {
    console.error('Error generating RSS feed:', error)
    return new Response('Error generating RSS feed', { status: 500 })
  }
}
