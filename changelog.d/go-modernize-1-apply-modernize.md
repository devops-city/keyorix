### Internal
- **Applied Go `modernize` fixes.** One-time mechanical pass of `golang.org/x/tools` v0.52.0 `modernize` (`any`, `for range n`, `min`/`max`, `slices.Contains`/`Sort`/`Backward`, `strings.SplitSeq`/`Cut*`, `maps.Copy`, `errors.AsType`, `sync.WaitGroup.Go`, `reflect.TypeFor`) across the root, `cli`, `operator`, `migrate` and `devtools` modules. No behaviour change.
