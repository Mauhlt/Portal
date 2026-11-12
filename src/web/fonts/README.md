# Bundled terminal font

The browser client (`src/wasm/`) rasterises text itself, so it ships its own
monospace font: an iPhone page cannot read system fonts. These files are
embedded into `app.wasm` at build time (see `build.zig`), not served
separately.

| file | sha256 |
|---|---|
| `DejaVuSansMono.ttf` | `b4a6c3e4faab8773f4ff761d56451646409f29abedd68f05d38c2df667d3c582` |
| `DejaVuSansMono-Bold.ttf` | `bce60f1b4421acd9ea51ba6623d7024ecbe6817a953e3654df62a5e6bdf8f769` |
| `LICENSE.txt` (the release's `LICENSE`) | `7a083b136e64d064794c3419751e5c7dd10d2f64c108fe5ba161eae5e5958a93` |

Source: the official DejaVu Fonts 2.37 release,
<https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_2_37/dejavu-fonts-ttf-2.37.zip>
(zip sha256 `7576310b219e04159d35ff61dd4a4ec4cdba4f35c00e002a136f00e96a908b0a`),
files `ttf/DejaVuSansMono.ttf`, `ttf/DejaVuSansMono-Bold.ttf` and `LICENSE`,
unmodified.

Licence: Bitstream Vera Fonts licence (DejaVu changes are public domain),
see `LICENSE.txt`. It permits redistribution, including bundled with
software, provided the copyright and permission notice is included; the
fonts are not modified or renamed here.
