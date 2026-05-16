#!/usr/bin/env node
/*
 * add-sha256-hashes.mjs
 *
 * Walks every manifest in the modpacks repo and adds a `sha256` field
 * to every file entry that has a `remote` URL but no usable SHA-256.
 * Existing `sha1` / `md5` / `sha256` fields are preserved as-is so the
 * launcher's strongest-first verification dispatch (SHA-256 → SHA-1 →
 * MD5) gets the strong hash without losing the weaker ones — old
 * launcher builds keep verifying via the SHA-1 they already understood.
 *
 * Scope: per-file entries inside packMods / packConfigs /
 * packResourcePacks / packShaderPacks / packInitialFiles. Top-level
 * loader hashes (packForgeHash / packModLoaderHash) are not touched —
 * those still flow through a single-hash code path in the loader
 * classes and won't read a packForgeSha256 even if it existed.
 *
 * Downloads are cached under tools/.sha256-cache/<sha1 of URL>.sha256
 * so re-runs are cheap. Pass --no-cache to ignore the cache.
 *
 * Usage:
 *   node tools/add-sha256-hashes.mjs              # update every manifest
 *   node tools/add-sha256-hashes.mjs --dry-run    # print would-add count, no writes
 *   node tools/add-sha256-hashes.mjs alto/manifest.json  # specific files
 */

import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { glob } from "node:fs/promises";

const args = process.argv.slice( 2 );
const dryRun = args.includes( "--dry-run" );
const noCache = args.includes( "--no-cache" );
const explicitTargets = args.filter( a => !a.startsWith( "--" ) );

const CACHE_DIR = resolve( "tools", ".sha256-cache" );
const REPO_ROOT = resolve( "." );
const FILE_LIST_KEYS = [
    "packMods",
    "packConfigs",
    "packResourcePacks",
    "packShaderPacks",
    "packInitialFiles",
];
const SENTINEL = "-1";
const MAX_PARALLEL = 6;

await mkdir( CACHE_DIR, { recursive: true } );

const manifests = explicitTargets.length > 0
    ? explicitTargets.map( t => resolve( t ) )
    : await collectManifests();

if ( manifests.length === 0 ) {
    console.error( "No manifest files found. Run from the repo root." );
    process.exit( 1 );
}

console.log( `Found ${manifests.length} manifest file(s).` );

let totalAdded = 0;
let totalSkippedExisting = 0;
let totalSkippedEmptyRemote = 0;
let totalFailed = 0;

for ( const manifestPath of manifests ) {
    const result = await processManifest( manifestPath );
    totalAdded += result.added;
    totalSkippedExisting += result.skippedExisting;
    totalSkippedEmptyRemote += result.skippedEmptyRemote;
    totalFailed += result.failed;
}

console.log( "\n=== Summary ===" );
console.log( `  Added sha256 to:      ${totalAdded} entries` );
console.log( `  Already had sha256:   ${totalSkippedExisting} entries` );
console.log( `  No remote URL:        ${totalSkippedEmptyRemote} entries` );
console.log( `  Download failures:    ${totalFailed} entries` );
if ( dryRun ) console.log( "  (--dry-run: no manifest files were modified)" );

async function collectManifests() {
    const out = [];
    // Top-level: any *.json that ends in manifest.json or matches the install list.
    for await ( const path of glob( "*/manifest*.json", { cwd: REPO_ROOT } ) ) {
        out.push( resolve( REPO_ROOT, path ) );
    }
    return out;
}

async function processManifest( manifestPath ) {
    const summary = { added: 0, skippedExisting: 0, skippedEmptyRemote: 0, failed: 0 };
    let manifest;
    try {
        manifest = JSON.parse( await readFile( manifestPath, "utf8" ) );
    }
    catch ( e ) {
        console.error( `  [skip] could not parse ${manifestPath}: ${e.message}` );
        return summary;
    }

    const relPath = manifestPath.replace( REPO_ROOT + "\\", "" ).replaceAll( "\\", "/" );
    console.log( `\n→ ${relPath}` );

    const tasks = [];
    for ( const key of FILE_LIST_KEYS ) {
        const arr = manifest[ key ];
        if ( !Array.isArray( arr ) ) continue;
        for ( const entry of arr ) {
            tasks.push( { entry, label: `${key}[${entry.name || entry.local || entry.remote || "?"}]` } );
        }
    }

    // Process in parallel batches so a big modpack doesn't take forever
    // but the network doesn't get hit with hundreds of concurrent connections.
    for ( let i = 0; i < tasks.length; i += MAX_PARALLEL ) {
        const batch = tasks.slice( i, i + MAX_PARALLEL );
        await Promise.all( batch.map( async ( { entry, label } ) => {
            try {
                const r = await maybeAddSha256( entry );
                if ( r === "added" ) {
                    summary.added++;
                    console.log( `  ✓ ${label}` );
                }
                else if ( r === "existing" ) summary.skippedExisting++;
                else if ( r === "no-remote" ) summary.skippedEmptyRemote++;
            }
            catch ( e ) {
                summary.failed++;
                console.error( `  ✗ ${label}: ${e.message}` );
            }
        } ) );
    }

    if ( !dryRun && summary.added > 0 ) {
        await writeFile( manifestPath,
                JSON.stringify( manifest, null, 2 ) + "\n", "utf8" );
        console.log( `  saved (added ${summary.added})` );
    }
    else if ( dryRun && summary.added > 0 ) {
        console.log( `  would-add ${summary.added} entries (--dry-run, not written)` );
    }
    else {
        console.log( `  nothing to add` );
    }
    return summary;
}

async function maybeAddSha256( entry ) {
    // Skip when the entry has no usable remote — there's nothing to fetch.
    const remote = entry.remote;
    if ( !remote || typeof remote !== "string" || remote.trim() === "" ) {
        return "no-remote";
    }

    // Skip when sha256 is already populated with a real value.
    if ( hasUsableHash( entry.sha256 ) ) {
        return "existing";
    }

    // Fetch (or pull from cache) and compute SHA-256.
    const sha256 = await sha256OfUrl( remote );
    entry.sha256 = sha256;
    return "added";
}

function hasUsableHash( v ) {
    return typeof v === "string" && v.trim() !== "" && v !== SENTINEL;
}

async function sha256OfUrl( url ) {
    // Cache key = SHA-1 of the URL so two manifests pointing at the same
    // CDN URL share one fetch + one stored hash.
    const cacheKey = createHash( "sha1" ).update( url ).digest( "hex" );
    const cachePath = join( CACHE_DIR, `${cacheKey}.sha256` );

    if ( !noCache && existsSync( cachePath ) ) {
        try {
            const cached = ( await readFile( cachePath, "utf8" ) ).trim();
            if ( /^[0-9a-f]{64}$/i.test( cached ) ) return cached;
        }
        catch { /* fall through to refetch */ }
    }

    const resp = await fetch( url );
    if ( !resp.ok ) {
        throw new Error( `HTTP ${resp.status} ${resp.statusText} for ${url}` );
    }
    const bytes = Buffer.from( await resp.arrayBuffer() );
    const sha256 = createHash( "sha256" ).update( bytes ).digest( "hex" );
    if ( !noCache ) {
        await writeFile( cachePath, sha256, "utf8" );
    }
    return sha256;
}
