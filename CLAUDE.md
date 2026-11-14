# Notes for Claude

- CI and release builds are deliberate, never routine: Actions minutes are
  scarce (private repos' Actions do not run; chatir's ci.yml is off by hand).
  Verify locally (`cargo fmt`, `clippy -D warnings`, tests). Never dispatch a
  workflow or push a tag to see whether something builds. A release is built
  once, when everything it ships is verified, merged and built as it should
  ship; not a version that is replaced hours later.
- The wire stays compatible with chatir v0.4.5 and later: frames (`FRAME`,
  seal, route), lanes (`pushir:ID:SECRET@RELAY`), `RELAY`, and the
  iroh-relay version the lab's relay speaks. Change it only when nothing
  else works, keeping the old form beside the new;
  `the_wire_is_as_chatir_v0_4_5` pins it.
- Each app's pushes depend on that app alone: never again one app's
  delivery through another's connection, version or settings.
