import type { LocalImageService } from 'astro'
import sharpService from 'astro/assets/services/sharp'
import { createHash } from 'node:crypto'
import sharp from 'sharp'

type Output = Awaited<ReturnType<LocalImageService['transform']>>

// Best full-size encode per source PNG, shared by all of its srcset widths
const fullSize = new Map<string, Promise<Output>>()

// Astro's sharp service only encodes lossy WebP, which blurs text in PNG
// screenshots and often comes out larger than the source. For PNG inputs,
// also encode a lossless WebP of the same resized pixels and keep the smaller.
// Transform hashes cover this file's path, not its contents: after editing it,
// clear node_modules/.astro/assets and bump the astro-v* cache key in deploy.yml.
const service: LocalImageService = {
  ...sharpService,
  async transform(input, options, config) {
    const lossy = await sharpService.transform(input, options, config)
    if (lossy.format !== 'webp') return lossy
    const { format, width, height } = await sharp(input).metadata()
    if (format !== 'png') return lossy

    const smallest = async (opts: typeof options, out: Output) => {
      // A PNG pass through Astro's own pipeline keeps resize, crop and
      // background exactly as in the lossy output
      const png = await sharpService.transform(
        input,
        { ...opts, format: 'png', quality: undefined },
        config,
      )
      const lossless = await sharp(png.data).webp({ lossless: true }).toBuffer()
      return lossless.length < out.data.length
        ? { data: lossless, format: out.format }
        : out
    }

    const best = await smallest(options, lossy)

    // Downscaling a screenshot adds anti-aliased edges that compress worse, so
    // a narrower srcset candidate can outweigh the full-size file. Serve the
    // full-size pixels then: the <img> width/height attributes fix the layout,
    // and the browser downscales them as it already does on 2x screens.
    if (
      !options.fit &&
      width &&
      height &&
      options.width &&
      options.width < width
    ) {
      const key = `${createHash('sha1').update(input).digest('hex')}:${options.quality ?? ''}`
      let full = fullSize.get(key)
      if (!full) {
        const opts = { ...options, width, height }
        full = sharpService
          .transform(input, opts, config)
          .then((out) => smallest(opts, out))
        fullSize.set(key, full)
      }
      const original = await full
      if (original.data.length < best.data.length) return original
    }
    return best
  },
}

export default service
