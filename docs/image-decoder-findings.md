# Image decoder findings (for the owner)

Portal decodes inline images with your Image package, pinned to
**Image@c64d400** (`../Image-wt-portal`, a detached worktree, used
read-only). Nothing in Image was changed. Portal wraps the decoder in
`client/src/image/imgdec.zig`:

1. `pngcheck.validate` first (Portal's own code): signature; IHDR CRC,
   legal depth/colour type, at most 8192 px per side and 32 Mpx; every
   chunk inside the file with a valid CRC and an alphabetic tag; PLTE
   before IDAT (required for palette images); consecutive IDATs; IEND;
   unknown critical chunks rejected; at most 4096 chunks and 6 MiB.
2. A cost check from the IHDR (inflated size, output, scratch) against a
   budget before anything is allocated.
3. `Image.PNG.info` + `Image.PNG.decodeInto` run on a bounded allocator
   capped at that budget.

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

### 1. `src/inflate/inflate.zig` does not compile for 32-bit targets (wasm32)

**Input:** none; this is a compile error. Build Image's PNG path for
`wasm32-freestanding` (Portal's browser client).

**Where:** three table lookups index arrays with the `u64` bit buffer
(`buf: u64`, line 321):

* line 184: `d.pre[b.buf & mask(pre_bits)]`
* line 403: `lt[b.buf & mask(lit_bits)]`
* line 473: `t.lit[buf & mask(lit_bits)]`

The error is `expected type 'usize', found 'u64'` wherever `usize` is
32 bits.

**Effect in Portal:** the browser client can't decode PNGs. It draws a
placeholder box with the image's pixel size instead
(`src/wasm/proto.zig`, `decoder_available`), and the inflate code is
never compiled into `app.wasm`. The window and `portal connect` decode
normally.

**Suggested fix:** cast the masked value at those three sites, for
example `d.pre[@as(usize, @intCast(b.buf & mask(pre_bits)))]`. The mask
keeps it far below 2^32, so `@truncate` works too. Once that is in a
commit Portal pins, the browser decodes with no other change in Portal.

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

**Suggested fix:** an optional limit in Image, e.g. `max_pixels` /
`max_side` passed to `info`/`decode` (or a package-level default such as
2^28 px) and checked in `header.decode`. Alternatively, document that
callers must check `info()` dimensions before calling `decodeInto`.

### 3. Note: the PNG decoder needs `vk.Format` (Vulkan bindings)

`info.zig` and `root.zig` carry a `vk.Format` field, so decoding a PNG
pulls in the `Vulkan` module. Natively Portal uses your published
`Image` module as is. For wasm32 it builds a module from the same
`src/root.zig` with a stub `Vulkan` that has only `Format`
(`client/src/image/vk_stub.zig`), so the bindings never enter the browser
build. A small `Format`-free "codecs" module in Image would remove the
need for the stub. That is optional.
