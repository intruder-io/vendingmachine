// _postlude.sc  — language-agnostic finish: flush the manifest + print summary.
// Concatenated AFTER the language fragment. Writes the prelude's `manifest`
// buffer (header comment lines + OK/UNRESOLVED entries) to disk.

val mpw = new PrintWriter(new File(s"$outputDir/manifest.txt"))
manifest.foreach(mpw.println)
mpw.close()

val okCount  = manifest.count(_.startsWith("OK"))
val badCount = manifest.count(_.startsWith("UNRESOLVED"))
println(s"=== Done: $okCount slices written, $badCount unresolved — output in $outputDir/ ===")
