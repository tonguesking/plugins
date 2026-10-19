#!/usr/bin/env node
/**
 * Registry validator — the machine gate behind `validate.yml`.
 *
 * Runs the same checks the desktop's install gate and the web's catalog
 * aggregation rely on, against the published `@polycreator/plugin-manifest`
 * package (REGISTRY_SCHEMA v2 + MARKETPLACE_MANIFEST_SCHEMA + the entry-hash
 * helpers). The goal: a PR that passes here is byte-consistent — a human then
 * only reviews code semantics (REVIEW.md).
 *
 * v2 entries are repo-level and dual-mode (one plugin = one repo = one
 * `releases/latest`):
 *   - latest (default, no tag/sha256): the author's release workflow uploads
 *     THREE assets — `<id>-<version>.zip`, the byte-identical alias
 *     `<id>.zip`, and `manifest.json` (the exact integrity-injected manifest
 *     bytes from inside the zip). Trust = PR review + the in-zip integrity.
 *   - pinned (`tag` + `sha256`, both or neither): the versioned
 *     `<id>-<version>.zip` asset, byte-verified against the pin.
 *
 * Gates (each one exits non-zero with a reason on failure):
 *   1. plugins.json parses + passes REGISTRY_SCHEMA v2 (id safe, repo shape,
 *      tag+sha256 paired, added_at ISO).
 *   2. ids are unique across the whole file.
 *   3. Diff is additive-only: the PR must not modify entries it doesn't own
 *      (compares the merged base against the head via GitHub's PR API).
 *   4. The GitHub repo exists and the right release + assets are there
 *      (latest mode: `releases/latest` holds both alias assets; pinned mode:
 *      the tag release holds the versioned asset).
 *   5. Asset bytes verify — pinned mode: sha256 matches the pin; latest
 *      mode: the `manifest.json` alias asset is byte-identical to the
 *      manifest inside the alias zip (no drift between probe and install).
 *   6. Unzipping yields a manifest passing MARKETPLACE_MANIFEST_SCHEMA,
 *      manifest.id == entry.id, and manifest.version == the release tag
 *      minus "v".
 *   7. The in-zip manifest's `integrity` matches the bytes it ships, computed
 *      with the same helper the desktop's install gate uses.
 *   8. Entries declaring a nodeEntry are flagged for manual review (a
 *      main-process entry is full-trust on the desktop).
 *
 * Usage (CI):
 *   REGISTRY_REPO=owner/plugins validate-registry.mjs <path-to-plugins.json>
 *   REGISTRY_REPO=owner/plugins validate-registry.mjs --pr <pr-number>
 */
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { unzipSync } from "fflate";
import {
	REGISTRY_SCHEMA,
	MARKETPLACE_MANIFEST_SCHEMA,
	digestEntryFiles,
	entryFileOrder,
	isPinnedEntry,
	registryLatestZipUrl,
	registryLatestManifestUrl,
	registryPinnedUrl,
} from "@polycreator/plugin-manifest";

const API = "https://api.github.com";
const UA = "polycreator-plugins-registry/1.0";
const HEADERS = {
	"User-Agent": UA,
	Accept: "application/vnd.github+json",
	// CI passes GITHUB_TOKEN (60 req/h unauthenticated would not survive
	// per-entry repo/release/asset checks).
	...(process.env.GITHUB_TOKEN
		? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
		: {}),
};

function die(msg, code = 1) {
	console.error(`validate-registry: ${msg}`);
	process.exit(code);
}

async function gh(pathname, opts = {}) {
	try {
		const res = await fetch(`${API}${pathname}`, { headers: HEADERS, ...opts });
		if (!res.ok) return null;
		return res.json();
	} catch (err) {
		die(`[4] GitHub API request failed for ${pathname}: ${err.message}`);
	}
}

async function download(url) {
	const res = await fetch(url, { headers: { "User-Agent": UA } });
	if (!res.ok) return null;
	return new Uint8Array(await res.arrayBuffer());
}

async function sha256Hex(bytes) {
	const digest = await crypto.subtle.digest("SHA-256", bytes);
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Unzip + MARKETPLACE_MANIFEST_SCHEMA + id/version match + pack --check
 *  (gates 6–7 shared by both modes). `expectedVersion` is the release tag
 *  minus "v" — both modes carry it (latest: from releases/latest). */
async function verifyUnpacked(entry, files, expectedVersion) {
	const manifestRaw = files["manifest.json"];
	if (!manifestRaw) throw new Error("[6] zip has no manifest.json");
	const manifest = JSON.parse(new TextDecoder().decode(manifestRaw));

	const parsed = MARKETPLACE_MANIFEST_SCHEMA.safeParse(manifest);
	if (!parsed.success) {
		throw new Error(
			`[6] manifest fails MARKETPLACE_MANIFEST_SCHEMA: ${parsed.error.issues
				.map((i) => i.path.join(".") + ": " + i.message)
				.join("; ")}`,
		);
	}
	if (manifest.id !== entry.id) {
		throw new Error(`[6] manifest.id "${manifest.id}" != entry.id "${entry.id}"`);
	}
	if (manifest.version !== expectedVersion) {
		throw new Error(`[6] manifest.version "${manifest.version}" != release tag minus v (${expectedVersion})`);
	}

	// Gate 7: the in-zip manifest's `integrity` must match the bytes it ships,
	// computed with the same helper the desktop's verifyPluginIntegrity uses
	// (`entryFileOrder` is the shared [main, nodeEntry?] order — a different
	// order, or one extra file mixed in, silently produces a different digest).
	// Accepts the bare hex form and the `sha256:` prefix, like the app does.
	const declared = String(manifest.integrity ?? "").trim();
	if (!declared) {
		throw new Error(`[7] ${entry.id} declares no integrity — the registry requires it (the app tolerates its absence for a local install)`);
	}
	const expected = declared.startsWith("sha256:") ? declared.slice("sha256:".length) : declared;
	if (!/^[a-f0-9]{64}$/.test(expected)) {
		throw new Error(`[7] ${entry.id} declares a malformed integrity value: ${declared.slice(0, 40)}`);
	}
	const entryBytes = new Map();
	for (const name of entryFileOrder(manifest)) {
		const bytes = files[name];
		if (!bytes) throw new Error(`[7] ${entry.id} declares "${name}" but the zip does not ship it`);
		entryBytes.set(name, bytes);
	}
	const actual = await digestEntryFiles(manifest, entryBytes);
	if (actual !== expected) {
		throw new Error(`[7] integrity mismatch for ${entry.id}: manifest declares ${expected}, bytes hash to ${actual}`);
	}
	return { nodeEntry: manifest.nodeEntry, manifestBytes: manifestRaw };
}

/** Latest mode (gates 4–7): both alias assets exist on `releases/latest`,
 *  alias manifest == in-zip manifest, then the shared unpacked checks. */
async function verifyLatestEntry(entry) {
	// Gate 4: repo + latest release + both alias assets. The `releases/latest`
	// REST endpoint only returns full (non-draft, non-prerelease) releases —
	// a 404 here means "no full release yet", which is exactly what we want
	// to refuse (the desktop's latest/download URL would 404 the same way).
	const release = await gh(`/repos/${entry.repo}/releases/latest`);
	if (!release) die(`[4] no full (non-draft/prerelease) release on ${entry.repo} — tag v* and publish one`);
	const assetNames = new Set((release.assets ?? []).map((a) => a.name));
	const aliasZipName = `${entry.id}.zip`;
	if (!assetNames.has(aliasZipName)) {
		die(`[4] latest release of ${entry.repo} is missing the alias asset "${aliasZipName}" (release workflow must upload all three assets)`);
	}
	if (!assetNames.has("manifest.json")) {
		die(`[4] latest release of ${entry.repo} is missing the "manifest.json" alias asset (release workflow must upload all three assets)`);
	}

	// Download the alias zip through the EXACT URL the desktop will use.
	const zipBytes = await download(registryLatestZipUrl(entry));
	if (!zipBytes) throw new Error(`[5] alias zip download failed: ${registryLatestZipUrl(entry)}`);

	const files = unzipSync(zipBytes);
	const { nodeEntry, manifestBytes } = await verifyUnpacked(
		entry,
		files,
		String(release.tag_name ?? "").replace(/^v/, ""),
	);

	// Gate 5 (latest mode): the standalone manifest.json alias asset must be
	// byte-identical to the manifest inside the zip — otherwise the desktop's
	// version probe and its install bytes disagree (alias drift).
	const aliasManifest = await download(registryLatestManifestUrl(entry.repo));
	if (!aliasManifest) throw new Error(`[5] manifest.json alias download failed: ${entry.repo}`);
	if (Buffer.compare(Buffer.from(aliasManifest), Buffer.from(manifestBytes)) !== 0) {
		throw new Error(
			`[5] manifest.json alias asset differs from the manifest inside ${aliasZipName} — re-run the release workflow so both come from the same pack`,
		);
	}

	return { nodeEntry };
}

/** Pinned mode (gates 4–7): the versioned asset, byte-verified against the
 *  sha256 pin — the original tamper-evidence flow. */
async function verifyPinnedEntry(entry) {
	const assetUrl = registryPinnedUrl(entry);
	// Gate 4: repo + tag release + derived asset name.
	const repoMeta = await gh(`/repos/${entry.repo}`);
	if (!repoMeta) die(`[4] repo not found: ${entry.repo}`);
	const release = await gh(`/repos/${entry.repo}/releases/tags/${encodeURIComponent(entry.tag)}`);
	if (!release) die(`[4] release tag not found: ${entry.repo}@${entry.tag}`);
	const assetName = assetUrl.split("/").pop();
	if (!release.assets?.some((a) => a.name === assetName)) {
		die(`[4] asset not found: ${assetName} in ${entry.repo}@${entry.tag}`);
	}

	const bytes = await download(assetUrl);
	if (!bytes) throw new Error(`[5] asset download failed: ${assetUrl}`);

	const actual = await sha256Hex(bytes);
	if (actual !== entry.sha256) {
		throw new Error(
			`[5] sha256 mismatch: pinned ${entry.sha256}, downloaded ${actual} — ` +
				"release bytes differ from what was reviewed",
		);
	}

	const files = unzipSync(bytes);
	const { nodeEntry } = await verifyUnpacked(entry, files, entry.tag.replace(/^v/, ""));
	return { nodeEntry };
}

async function main() {
	const argv = process.argv.slice(2);
	const prFlag = argv.indexOf("--pr");
	let pluginsPath;
	let prNumber = null;

	if (prFlag !== -1) {
		prNumber = argv[prFlag + 1];
		pluginsPath = argv.filter((_, i) => i !== prFlag && i !== prFlag + 1)[0];
	} else {
		pluginsPath = argv[0];
	}
	if (!pluginsPath) die("missing <path-to-plugins.json> argument");
	if (!existsSync(pluginsPath)) die(`file not found: ${pluginsPath}`);

	const raw = JSON.parse(await readFile(pluginsPath, "utf8"));
	const parsed = REGISTRY_SCHEMA.safeParse(raw);
	if (!parsed.success) {
		die(
			`[1] plugins.json fails REGISTRY_SCHEMA: ${parsed.error.issues
				.map((i) => i.path.join(".") + ": " + i.message)
				.join("; ")}`,
		);
	}
	const plugins = parsed.data.plugins;

	// Gate 2: unique ids.
	const seen = new Set();
	for (const p of plugins) {
		if (seen.has(p.id)) die(`[2] duplicate id "${p.id}"`);
		seen.add(p.id);
	}

	// Gate 3: additive-only diff (only meaningful on a PR).
	if (prNumber) {
		const repo = process.env.REGISTRY_REPO;
		if (!repo) die("REGISTRY_REPO env required with --pr");
		const pr = await gh(`/repos/${repo}/pulls/${prNumber}`);
		if (!pr) die(`[3] could not read PR ${prNumber}`);
		const baseRaw = await gh(`/repos/${repo}/contents/plugins.json?ref=${pr.base.sha}`);
		const headRaw = await gh(`/repos/${repo}/contents/plugins.json?ref=${pr.head.sha}`);
		const base = baseRaw
			? JSON.parse(Buffer.from(baseRaw.content, "base64").toString())
			: { plugins: [] };
		const head = headRaw
			? JSON.parse(Buffer.from(headRaw.content, "base64").toString())
			: { plugins: [] };
		const baseIds = new Map(base.plugins.map((p) => [p.id, p]));
		const headIds = new Map(head.plugins.map((p) => [p.id, p]));
		// Ownership = the PR AUTHOR's login, not pr.head.repo.full_name —
		// PRs come from forks, so the fork's full_name never equals the
		// plugin repo an entry points at; comparing them rejects every
		// legitimate external update. What we actually require: every
		// plugin repo an entry touches belongs to the submitter.
		const submitter = pr.user.login;
		const ownerOf = (entry) => entry.repo.split("/")[0];
		// Official entries (plugin repo under the registry's own org) may be
		// submitted by any org member — the repo owner is the org itself, so
		// the personal-ownership rule can never pass for them. Membership is
		// checked live; non-members submitting org-owned repos still fail.
		const registryOrg = repo.split("/")[0];
		const orgMembers = new Set();
		try {
			const members = await gh(`/orgs/${registryOrg}/members?per_page=100`);
			if (Array.isArray(members)) for (const m of members) orgMembers.add(m.login);
		} catch {
			// membership lookup failed — fall through to the strict rule
		}
		const isOfficialEntry = (entry) => ownerOf(entry) === registryOrg;
		const maySubmit = (entry) =>
			ownerOf(entry) === submitter || (isOfficialEntry(entry) && orgMembers.has(submitter));
		for (const [id, headEntry] of headIds) {
			const baseEntry = baseIds.get(id);
			if (!baseEntry) {
				// New entry: the submitter must own the plugin repo it pins
				// (org members may submit org-owned official entries).
				if (!maySubmit(headEntry)) {
					die(`[3] new entry "${id}" pins ${headEntry.repo} but PR is from @${submitter} — you may only submit entries for repos you own`);
				}
				continue;
			}
			// Modified entry: no repo swap, and only the owning repo's author
			// may change it.
			if (headEntry.repo !== baseEntry.repo) {
				die(`[3] entry "${id}" changed repo (${baseEntry.repo} → ${headEntry.repo}) — modifying others' entries is not allowed`);
			}
			if (!maySubmit(baseEntry)) {
				die(`[3] entry "${id}" belongs to ${baseEntry.repo} but PR is from @${submitter} — modifying others' entries is not allowed`);
			}
		}
		// Removals follow the same rule: you may only remove your own entries.
		for (const [id, baseEntry] of baseIds) {
			if (!headIds.has(id) && !maySubmit(baseEntry)) {
				die(`[3] PR removes "${id}" (repo ${baseEntry.repo}) owned by @${ownerOf(baseEntry)} — PR is from @${submitter}`);
			}
		}
	}

	// Gates 4–8 per entry, mode-routed. `official` is derived at read time from
	// the entry's repo owner (see isOfficial in @polycreator/plugin-manifest) —
	// the registry never carries the flag, so no gate is needed here.
	for (const entry of plugins) {
		const { nodeEntry } = isPinnedEntry(entry)
			? await verifyPinnedEntry(entry)
			: await verifyLatestEntry(entry);

		// Gate 8: nodeEntry ⇒ manual review required. Exit code 2 (not 1) —
		// validate.yml treats it as "label needs-manual-review", not failure.
		if (nodeEntry) {
			console.log(`[8] ${entry.id} declares nodeEntry — requires manual review`);
			process.exitCode = 2;
		}
	}

	console.log(`validate-registry: ${plugins.length} entries OK`);
}

main().catch((err) => {
	const cause = err instanceof Error && err.cause ? ` (${err.cause.message ?? err.cause})` : "";
	die(`${err instanceof Error ? err.message : String(err)}${cause}`);
});
