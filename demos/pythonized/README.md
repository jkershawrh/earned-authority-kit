# Earned Authority · A paper-cutout trial

First application of the expanded `pythonize-demo` skill. Original repo-derived artwork, cheeky narration, page-specific compositions, and articulated paper animation follow the kit's qualification → grant → mutation fence → independent readback → selective withdrawal → requalification lifecycle.

## Open locally

```sh
python3 server.py --repo /absolute/path/to/earned-authority-kit --port 5184
```

Open `http://127.0.0.1:5184`. Use the kit's Python environment; the bridge imports its unchanged `earned_authority.runtime` and requires its dependencies, including cryptography. When this folder is installed as `demos/pythonized` inside the kit, the repo path is detected automatically. The preview binds only to loopback.

State lives in a separate temporary directory and is removed when the server closes normally. It never mutates the kit's reference installations, real model registry, service keys, or tracked evidence. This is **M1 LOCAL_FIXTURE**, with fixture authority and Ledger, real SQLite registry mutations, signatures, independent readback, and source-runtime enforcement. It is not a connected-canonical-services run or a business-value evaluation.

## Rehearse the lifecycle

1. On **Independent qualification**, run three independent PASS shadow trials and evaluate qualification. The returned disposition is ELIGIBLE; no permission has been issued. Try self-report, UNKNOWN or FAIL in a reset experiment to see the source's refusal/hold behavior.
2. On **Bounded permission**, request the grant. The ornate shutter follows the source's current authorization check. Policy denial remains separate from qualification.
3. On **The mutation fence**, admit and commit. To test revocation fencing, admit, revoke, then commit. To test expiry, advance the controlled clock. The registry and mutation count show the actual returned state.
4. On **Independent readback**, read the registry and verify signed fixture receipt evidence. Inspect or download the full trace.
5. For selective withdrawal, first qualify and grant `read-health`. Admit another release, enable the wrong-result fault and commit. Apply its independently observed FAIL on the withdrawal page. The release grant is removed; the read-health grant remains usable.
6. Qualify revised `skill-v2`, then separately request its new grant. Requalification does not reactivate the old procedure or mutate the registry.
7. Inspect the recorded roadmap. It remains a recorded repository report with its timestamp and broader AMBER boundary; the demo does not refresh or upgrade acceptance.

Navigation, animation replay, and pause do not execute the pipeline. Pipeline actions are explicit buttons. Page 04's fault controls deliberately inject local outcomes; they are not real infrastructure incidents. The default shadow profile is the kit's three-pass demonstration rule, not statistical confidence.

## Controls and presentation

Chapters, arrows, Page Up/Page Down, and Space outside focused controls navigate. **P** toggles presenter narration. Pause suspends motion while leaving navigation readable. Replay resets visual choreography only. Fullscreen and an evidence inspector are available. Reduced motion shows stable poses. Narrow screens use a vertically readable rehearsal layout.

Narration is written presenter text; no synthesized voice or music is included. `earned-authority-rehearsal-v2.webm` is the current normal-motion capture of local-fixture actions for pacing review, not a production video or connected-service evidence.

## Revised framing

The current treatment replaces the card-like frames with torn receipts, a suspended evidence line, a folded scope scroll, a listening anatomical lock, scalloped paper seals, detachable skill limbs, and separately hinged engraved shears. The top/bottom controls use a lighter paper-theatre frame. Artwork, layout, and choreography change; the source runtime and proof semantics remain unchanged.

Upright Caslon-style headings, Baskerville narration and typewriter evidence labels provide a period-print hierarchy. Italics are reserved for spoken asides. Fonts use local system stacks with portable fallbacks.

The original `earned-authority-rehearsal.webm` is retained as the first treatment.

## Files and checks

`production-notes.md` contains the repo-to-treatment mapping, script, visual bible, and verification boundary. `art/manifest.json` records local assets, dimensions, reference continuity, transparency, and rig pivots. `art/prompts.md` records generation directions. Raster assets were created with the built-in image-generation tool; graphics, labels, diagrams, and movable layers are native code.

```sh
python3 -m unittest discover -s tests -v
```

Browser verification uses Playwright:

```sh
npm install --no-save playwright
npx playwright install chromium
node tests/browser.cjs
```

Start the preview on port 5184 first. Tests exercise disposable fixture state, three viewports, the complete lifecycle, pause and navigation, and replay without extra runtime actions. Artifact screenshots are diagnostic outputs.
