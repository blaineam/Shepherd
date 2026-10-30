# Vendored third-party files

Everything the portal needs is served from this directory. There is no CDN, no
tile service and no remote asset, so the portal works offline and the strict
Content-Security-Policy (`default-src 'self'`) holds.

| File | Package | Version | License | Source |
| --- | --- | --- | --- | --- |
| `three.module.min.js` | `three` | 0.186.1 | MIT (`three.LICENSE`) | https://registry.npmjs.org/three/-/three-0.186.1.tgz |
| `land-110m.json` | `world-atlas` | 2.0.2 | ISC package license (`world-atlas.LICENSE`); the data is Natural Earth, public domain | https://registry.npmjs.org/world-atlas/-/world-atlas-2.0.2.tgz |

## How they were produced

`three.module.min.js` is `three@0.186.1`'s `build/three.module.js` bundled with
its `three.core.js` into a single minified ES module (all exports kept, nothing
tree-shaken), using esbuild 0.28.2:

```
npm i three@0.186.1 world-atlas@2.0.2 esbuild@0.28.2   # in a scratch directory
echo "export * from 'three';" > entry.js
npx esbuild entry.js --bundle --minify --format=esm --legal-comments=none --outfile=three.module.min.js
```

`land-110m.json` is copied unchanged from `node_modules/world-atlas/land-110m.json`
(Natural Earth 1:110m land, TopoJSON).

## SHA-256

```
6bff6b08121fc77918fe8e5d4a323d51f27acc13cf869bb9af51946e275acc2b  three.module.min.js
8b378ebe60e2fe500158cb0ac71cb5e8b7d92953c2abcc63a0eb90499653b5bc  three.LICENSE
ead5f68119c49a9250902e7da303bcb209341bbb8fefe7369a439b48b704658a  land-110m.json
8048290dfdb6e83fbed17e8985c8cfc4ce9da9b842642f3d3e497280790cfa31  world-atlas.LICENSE
```

To update: repeat the steps above in a scratch directory outside the repo, copy
the files here, and refresh the versions and hashes in this file.
