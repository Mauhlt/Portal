# Image decoder findings (for the owner)

Portal checks and decodes inline images with your Image package. It
builds on branch **image-check** of your Image repo (worktree
`../Image-wt-check`, see `build.zig.zon`); once you merge that branch into
your Image branch, Portal's dependency becomes `../Image`, the de-facto
Image, and every Portal build follows its latest commit. Image itself
depends on `../Vulkan`.

The pre-decode checks now live in Image: **`Image.check`** (module
"ImageCheck", `src/check`, std only, builds for wasm32). Portal's own
`client/src/image/imgcheck.zig` only picks the format (PNG) and the limits.
Portal wraps the decoder in `client/src/image/imgdec.zig`:

1. `imgcheck.validate` = `Image.check.checkAs(.png, bytes, limits)`:
   signature; IHDR CRC, legal depth/colour type, at most 8192 px per side
   and 32 Mpx; every chunk inside the file with a valid CRC and an
   alphabetic tag; PLTE before IDAT (required for palette images);
   consecutive IDATs; IEND; unknown critical chunks rejected; at most 4096
   chunks and 6 MiB. The server (`src/vt_gfx.zig`) runs the same check
   before storing or forwarding an image.
2. A cost check against a budget before anything is allocated:
   `Image.check`'s `decode_bytes` (inflated rows, concatenated IDATs, a
   zero row, the decoder's output) plus Portal's RGBA copy and scaler.
3. `Image.PNG.info` + `Image.PNG.decodeInto` run on a bounded allocator
   capped at that budget.

### `Image.check` in short

```zig
const check = @import("ImageCheck"); // or Image.check
const info = try check.check(bytes, .{ .max_bytes = 8 << 20, .max_pixels = 16 << 20 });
// info.format (.png, .jpg, .webp, ...), info.width, info.height,
// info.channels, info.bits, info.decode_bytes; info.png for PNGs.
```

* `check` / `checkAs(format, ...)`: detect (or take) the format and walk
  the whole structure; `checkHeader` / `checkHeaderAs`: size only.
* `Limits`: `max_bytes`, `max_width`, `max_height`, `max_pixels`,
  `max_decode_bytes`, `max_chunks` (defaults finite; `Limits.none`).
* Precise errors: `UnknownFormat`, `UnsupportedFormat` (GIF, TIFF),
  `UnsupportedFeature`, `Truncated`, `InvalidHeader`, `InvalidDimensions`,
  `InvalidBitDepth`, `InvalidColorType`, `InvalidCompression`,
  `InvalidFilterMethod`, `InvalidInterlaceMethod`, `InvalidChunk`,
  `InvalidCrc`, `InvalidChunkOrder`, `MissingImageData`, `MissingEnd`,
  `TooManyChunks`, `FileTooLarge`, `ImageTooLarge`, `DecodeTooLarge`.
* Formats: PNG (full chunk walk; the PNG codec shares its IHDR rules and
  CRC), JPEG (SOF0-3, segments to the first scan, DNL) and JPEG-LS, BMP,
  WebP (VP8, VP8L, VP8X), QOI, TGA, PBM/PGM/PPM/PAM, HEIC (primary item's
  `ispe` + `irot`), DDS, KTX2.
* Tested: per-format cases, a fuzz over every format, and agreement with
  the decoders on every file in Image's `src/Data/Read`.

## Fuzzing done

All in Debug (safety checks on), under `zig build test`:

* `imgdec.zig` "fuzz": 3000 rounds per run (200,000 in a one-off
  campaign) of mutated, truncated, IHDR-rewritten and IDAT-split PNGs.
  Seeds: Portal's stored-deflate writer, your own PNG encoder, and
  gray/palette/16-bit/interlaced headers over random deflated data. CRCs
  are re-fixed on most rounds so the mutations get past the CRC check.
* A one-off campaign of 300,000 inputs straight into `Image.PNG.info` /
  `decodeInto` **without** Portal's pre-validation. Inputs: random
  1-20 px images of every colour type, depth and interlace; random
  palettes of 0-100 entries; inserted tRNS/PLTE/IDAT/IEND/IHDR/sRGB/gAMA/
  pHYs chunks of random length; byte flips; CRCs fixed.
* A zlib bomb test: a 2048 x 2048 RGBA image whose IDAT inflates to 4x
  the image size.

**Results:** no crash, hang or out-of-bounds access in any of it. Inflate
writes only into the buffer sized from the IHDR, so the zlib bomb costs
exactly that buffer. Malformed data comes back as errors.

## Findings

### 1. `src/inflate/inflate.zig` did not compile for 32-bit targets (wasm32) - FIXED in image-check

Table lookups indexed arrays with the `u64` bit buffer (`d.pre[b.buf &
mask(pre_bits)]` and 13 more sites), a compile error where `usize` is 32
bits. image-check indexes through a `low(buf, n)` helper that truncates
the masked value to `usize` (free on 64-bit). The PNG decoder now
compiles for wasm32-freestanding (Portal's browser client used that; it
has since been removed).

### 2. A ~50-byte file can make the decoder try to allocate tens of GiB

**Input:** a valid PNG whose IHDR claims 65535 x 65535, 16-bit RGBA,
followed by a tiny IDAT.

**Where:**

* `Formats/png/header.zig` `decode` only rejects a `width * height`
  that overflows `u32`, so up to about 4.29 Gpx passes.
* `root.zig` `decode` then allocates `inf.byteLen()`, about 17 GB for
  RGBA8 output.
* `png.zig` `decodeWith` allocates `raw` (`h * (rowBytes + 1)`, about
  34 GB for 16-bit RGBA) before inflating anything.

**Effect:** with a normal allocator this becomes an `OutOfMemory` error,
not a crash. Still, any caller that decodes untrusted files through
`Image.decode` / `Image.read` can be pushed into huge allocation
attempts. On systems that overcommit, that can mean real memory pressure.
Portal is not affected: it checks the IHDR first, then the budget, and
uses a bounded allocator.

**Now:** `Image.check` is that limit: callers that decode untrusted files
run `check.check(bytes, limits)` first and get `ImageTooLarge` /
`DecodeTooLarge` before any allocation. `Image.decode` itself still
trusts its input; a default `check` inside `decode` is a possible next
step.

### 3. Note: the PNG decoder needs `vk.Format` (Vulkan bindings)

(`Image.check` does not: it is std only. This note is about decoding.)


`info.zig` and `root.zig` carry a `vk.Format` field, so decoding a PNG
pulls in the `Vulkan` module. Portal uses your published `Image` module
as is (every Portal build has Vulkan anyway, now that the wasm browser
client and its stub `Vulkan` are gone).
