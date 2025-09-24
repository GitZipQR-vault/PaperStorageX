# PaperStorageX  

**Printable Secure Storage — Multi-page, Flexible Formats, Always-On Encryption**  

PaperStorageX is a C++ utility that lets you archive and encrypt arbitrary data, encode it into printable PDF pages, and later reconstruct it back with full cryptographic integrity.  

---

## Core Features
- **Encryption always enabled** — AES-256-GCM with per-page nonce + tag.  
- **Key derivation** — scrypt (configurable N/r/p, salt stored per volume).  
- **Page geometry** — binary raster, default 1200 DPI (A-series, custom, or experimental).  
- **Resilient format** — each page has a self-contained 512-byte header + ciphertext block.  
- **Integrity** — full-volume SHA-256 (over plaintext) checked on decode.  

---

## Supported Flags / Options

### General
```bash
--password <any password type>   # Use any password type
--bin <file with password .bin>         # Use raw binary password from file
--folder <dir where throw data in PDF format>
--type <tar|zip>     # Archive input directory as TAR (default) or ZIP
--quiet              # Suppress logs
--no-tty             # For non-interactive environments
--page A4            # 11760×8268 @ 1200 DPI (default)
--page A3            # Larger payload (≈ 2× A4)
--page A2, A1, A0    # Even larger; scales by ISO A-series
--dpi <number>       # Custom resolution, overrides built-in presets

# Example:
-- page A0 --dpi 2400 gives massive payload per sheet.

# Advanced Formats
--nanotech           # Hypothetical "nanotech mode" — experimental layout 
                     # pushes density to theoretical limit (~500 TB per page).
--hybrid             # Hybrid mode combining multiple encoding layers (multi-bit + CMYK).
--gpi <level>        # Granularity Per Inch — sets modulation depth for custom density.
--levels <n>         # Use N intensity levels per pixel (multi-bit symbols).
-- ⚠️ Note: --nanotech, --hybrid, --gpi, --levels are forward-looking / experimental flags.
They define how data bits are mapped to printable cells. Not all printer/scanner pairs will survive these densities.
```
# CLI USAGE
- Encode
```bash
./paperx encode --bin secret.bin --page A3 docs/ archive
```
- Decode
```bash
./paperx decode --bin secret.bin archive.pdf restored.tar
```
- Reads all pages, validates UUID, GCM tags, SHA-256 checksum, then restores plaintext.

# Print / Scan Guidance
- Print 1:1 scale at chosen DPI (disable “fit to page”).
- Disable filters: no contrast boost, no smoothing, no auto-deskew.
- Scan back at the same DPI, lossless (PNG/TIFF).

# Next Steps (roadmap)
- Page-level forward-error correction (RS/Fountain codes).
- OpenCV-based auto-deskew and fiducial alignment.
- Real implementation of --nanotech and --hybrid.
- Integration with distributed “paper vault” libraries.