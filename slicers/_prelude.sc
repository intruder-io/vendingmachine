// _prelude.sc  — language-AGNOSTIC core of the surface slicer
//
// This fragment is concatenated by run_surface_slices.sh in front of a
// language fragment (php.sc / ruby.sc) and _postlude.sc, then run as a single
// `joern --script` file. It owns everything that is independent of the target
// language:
//
//   * config (env vars), CPG loading (semantic overlays only — no dataflow),
//   * source reading (getMethodSource / sourceWindow),
//   * downstream call-tree walking (collectCallees),
//   * slice/manifest output + cross-pass dedupe (writeSliceFile / emit / ...).
//
// CONTRACT for language fragments (enforced by a grep lint in the runner):
//   - The prelude owns ALL shared `val`s and mutable buffers: `cpg`, `manifest`,
//     `emitted`, `usedSlugs`, and the config vals. A language fragment must NOT
//     redefine any of these (a shadowing `val manifest` silently breaks the
//     postlude, which flushes the prelude's buffer).
//   - Language fragments only READ these and CALL emit / emitUnresolved.
//   - Each language fragment defines its own input predicate under a distinct
//     name (readsRequestInputPhp / readsRequestInputRuby) — never shadow a def.
//   - No `@main` anywhere.

import java.io.{File, PrintWriter}
import scala.io.Source
import scala.util.{Try, Using}
import io.shiftleft.codepropertygraph.cpgloading.CpgLoader
import io.joern.x2cpg.X2Cpg.applyDefaultOverlays

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
val project = sys.env.getOrElse("PROJECT", {
  println("[!] PROJECT env var is required."); sys.exit(1); ""
})
val sourceRoot = sys.env.getOrElse("SOURCE_ROOT", {
  println("[!] SOURCE_ROOT env var is required."); sys.exit(1); ""
})
val outputBase   = sys.env.getOrElse("OUTPUT_BASE", "surface_slices")
val maxCallDepth = sys.env.getOrElse("MAX_DEPTH", "10").toInt
val skipDirs     = sys.env.getOrElse("SKIP_DIRS", "vendor/,node_modules/,tests/,test/,/Test,.min.")
                     .split(",").map(_.trim).filter(_.nonEmpty).toList
// LANGUAGE/SKILL are informational: recorded in the manifest header so the
// runner/consumer knows which triage skill to invoke. Optional (default unknown).
val language = sys.env.getOrElse("LANGUAGE", "unknown")
val skill    = sys.env.getOrElse("SKILL", "")

val outputDir = s"$outputBase/$project"
val cpgDir    = "cpgs"
val cpgFile   = s"$cpgDir/$project.bin"

def isSkipped(filename: String): Boolean = {
  val f = if (filename == null) "" else filename
  skipDirs.exists(f.contains)
}

// ---------------------------------------------------------------------------
// CPG management
//
// IMPORTANT — why we don't use loadCpg/importCpg/importCode here:
// Those console helpers apply Joern's *default overlays*, which include the OSS
// dataflow layer (io.joern.dataflowengineoss.layers.dataflows.OssDataFlow). That
// layer builds per-method reachability bitsets and its memory cost explodes on
// large codebases — on a big tree it OOMs the JVM during overlay creation,
// importCode/loadCpg throw, and you get an empty CPG that silently finds nothing.
//
// This script never calls reachableByFlows / dataflow, so we load the CPG and
// apply ONLY the semantic overlays (Base + ControlFlow + TypeRelations +
// CallGraph) via X2Cpg.applyDefaultOverlays — which is what gives us `.callee`,
// the call graph, and AST traversal — and we DO NOT add dataflow. This loader is
// frontend-agnostic: a CPG produced by php2cpg or rubysrc2cpg loads identically
// (the .bin is the language-neutral CPG schema). Note that callee-edge quality is
// frontend-dependent (rubysrc2cpg resolves far fewer than php2cpg), so collectCallees
// is thinner on Ruby — the language fragment flags that in the manifest header.
//
// For large trees, prebuild the CPG out-of-process with the appropriate frontend
// and a big heap; see run_surface_slices.sh.
// ---------------------------------------------------------------------------
new File(cpgDir).mkdirs()

val cpg =
  if (new File(cpgFile).exists()) {
    println(s"[*] Loading prebuilt CPG from $cpgFile (semantic overlays only, no dataflow) ...")
    val c = CpgLoader.load(cpgFile)
    applyDefaultOverlays(c)   // Base/ControlFlow/TypeRelations/CallGraph — NOT OssDataFlow
    println(s"[*] CPG loaded: ${c.method.size} methods")
    c
  } else {
    // No prebuilt CPG: parse in-process (frontend auto-detected from sources).
    // Fine for small apps; on large trees the default heap + dataflow overlay will
    // OOM — prebuild the CPG with run_surface_slices.sh instead.
    println(s"[*] No CPG at $cpgFile — parsing $sourceRoot with importCode ...")
    try {
      val c = importCode(inputPath = sourceRoot, projectName = project)
      println(s"[*] CPG created in workspace as project '$project'")
      c
    } catch {
      case t: Throwable =>
        val msg = Option(t.getMessage).getOrElse(t.getClass.getName)
        println(s"[!] importCode failed ($msg).")
        println(s"[!] For large codebases this is almost always an OutOfMemoryError in the")
        println(s"[!] dataflow overlay. Prebuild the CPG out-of-process with the appropriate")
        println(s"[!] frontend (php2cpg / rubysrc2cpg) and a large heap, then re-run — see")
        println(s"[!] run_surface_slices.sh.")
        new File(outputDir).mkdirs()
        new PrintWriter(new File(s"$outputDir/failed.txt")) { println(msg); close() }
        sys.exit(1)
        throw t  // unreachable; satisfies the type checker
    }
  }

println(s"[*] Project:  $project")
println(s"[*] Language: $language")
println(s"[*] Source:   $sourceRoot")
println(s"[*] Output:   $outputDir")
println(s"[*] Skipping: ${skipDirs.mkString(", ")}")
println()

// ---------------------------------------------------------------------------
// Core helpers (language-agnostic; shared across all slice scripts)
// ---------------------------------------------------------------------------

def getMethodSource(m: Method): String = {
  val start    = m.lineNumber.getOrElse(1)
  val end      = m.lineNumberEnd.getOrElse(start)
  val fullPath = new File(sourceRoot, m.filename).getPath
  // Primary: read the real source lines (PHP/Ruby/Java-source frontends set
  // `filename` to a path relative to sourceRoot, so this works).
  val fromFile = Try {
    Using.resource(Source.fromFile(fullPath)) { src =>
      src.getLines().slice(start - 1, end).mkString("\n")
    }
  }.toOption.filter(_.trim.nonEmpty)
  // Fallback: bytecode frontends (e.g. jimple2cpg) set `filename` to a transient
  // extracted `.class` path that no longer exists and isn't .java anyway — there
  // is no source to read. Render the method's lowered body straight from the CPG
  // instead (jimple2cpg stores the full Jimple IR in METHOD.code, which shows the
  // calls, string concatenations, sinks, etc. an analyst needs). Harmless for the
  // source frontends, where fromFile already succeeded.
  fromFile.getOrElse {
    Try(m.code).toOption.filter(_.trim.nonEmpty)
      .map(b => s"// [no source file — rendered from CPG (lowered/IR body)]\n$b")
      .getOrElse(s"// Could not read source for ${m.fullName} from $fullPath")
  }
}

def collectCallees(m: Method, depth: Int = maxCallDepth, seen: Set[String] = Set.empty): Set[Method] = {
  if (depth == 0) return Set.empty
  val direct = m.callee
    .filterNot(c => c.isExternal || seen.contains(c.fullName))
    .nameNot("<operator>.*")
    .l.toSet
  val newSeen = seen ++ direct.map(_.fullName)
  direct ++ direct.flatMap(c => collectCallees(c, depth - 1, newSeen))
}

// Read a window of source lines starting at a call's line — used by language
// fragments to inspect callbacks that live inside arrays / strings / blocks.
def sourceWindow(call: Call, windowLines: Int = 8): String = {
  val line     = call.lineNumber.getOrElse(1)
  val file     = Try(call.method.filename).getOrElse("")
  val fullPath = new File(sourceRoot, file).getPath
  Try {
    Using.resource(Source.fromFile(fullPath)) { src =>
      src.getLines().toArray.slice(line - 1, line + windowLines).mkString("\n")
    }
  }.getOrElse("")
}

// Parse a BLOCK argument lowered from an array callback: [$this,'m'] / [Class::class,'m'].
// (PHP-style lowering; harmless for other languages — they simply don't call it.)
def parseBlockCallback(block: nodes.Expression): Option[(String, String)] = {
  val children = block.astChildren.code.l
  val methodPat = """\[1\]\s*=\s*["'](\w+)["']""".r
  val classPat  = """\$(\w+)\.__construct@""".r
  val meth = children.collectFirst {
    case s if methodPat.findFirstMatchIn(s).isDefined =>
      methodPat.findFirstMatchIn(s).get.group(1)
  }
  val cls = children.collectFirst {
    case s if classPat.findFirstMatchIn(s).isDefined =>
      classPat.findFirstMatchIn(s).get.group(1)
  }
  (cls, meth) match {
    case (Some(c), Some(m)) => Some((c, m))
    case (None,    Some(m)) => Some(("", m))
    case _                  => None
  }
}

// ---------------------------------------------------------------------------
// Output helpers (slice file + manifest; identical format across languages so
// the triage skills consume any language's output the same way)
// ---------------------------------------------------------------------------

new File(outputDir).mkdirs()
val manifest  = collection.mutable.ListBuffer[String]()
val usedSlugs = collection.mutable.Map[String, Int]()
val emitted   = collection.mutable.Set[String]()  // entry fullNames already sliced (dedupe across types)

// Manifest header: comment lines (ignored by the OK/UNRESOLVED parser) that tell
// the consumer the language and which triage skill to invoke.
manifest += s"# Language: $language"
if (skill.nonEmpty) manifest += s"# Skill: $skill"
manifest += s"# Project: $project"

def safeSlug(s: String): String = s.replaceAll("[^a-zA-Z0-9_\\-]", "_").take(60)

def uniqueOutFile(slugBase: String): String = {
  val n = usedSlugs.getOrElse(slugBase, 0)
  usedSlugs(slugBase) = n + 1
  if (n == 0) s"$outputDir/$slugBase.txt"
  else        s"$outputDir/${slugBase}_$n.txt"
}

def writeSliceFile(
  entryType: String, label: String, cbDesc: String,
  entry: Method, callees: Set[Method], outFile: String,
  extra: Seq[(String, String)] = Nil
): Unit = {
  val allMethods = (callees + entry).toList.sortBy(m => (m.filename, m.lineNumber.getOrElse(0)))
  val pw = new PrintWriter(new File(outFile))
  pw.println(s"// Type:       $entryType")
  pw.println(s"// Label:      $label")
  pw.println(s"// Callback:   $cbDesc")
  pw.println(s"// Entry:      ${entry.fullName}")
  pw.println(s"// File:       ${entry.filename}:${entry.lineNumber.getOrElse("?")}")
  extra.foreach { case (k, v) => pw.println(s"// $k: $v") }
  pw.println(s"// Downstream: ${callees.size} functions")
  pw.println(s"// Slice size: ${allMethods.size} functions")
  pw.println(s"// ${"=" * 60}")
  pw.println()
  allMethods.foreach { m =>
    pw.println(s"// --- ${m.fullName} ---")
    pw.println(s"// ${m.filename}:${m.lineNumber.getOrElse("?")}–${m.lineNumberEnd.getOrElse("?")}")
    pw.println(getMethodSource(m))
    pw.println()
  }
  pw.close()
}

def emit(
  entryType: String, label: String, cbDesc: String,
  entry: Method, extra: Seq[(String, String)] = Nil
): Unit = {
  // Global dedupe by entry: passes run highest-signal first, so a function
  // reachable via a framework route is sliced once under ROUTE rather than again
  // under the INPUT_SOURCE catch-all.
  if (emitted.contains(entry.fullName)) return
  emitted += entry.fullName
  val callees = collectCallees(entry)
  val slug    = safeSlug(s"${entryType}_${label}")
  val outFile = uniqueOutFile(slug)
  writeSliceFile(entryType, label, cbDesc, entry, callees, outFile, extra)
  val total = callees.size + 1
  manifest += s"OK [$entryType]: $label -> ${entry.fullName} [$outFile] ($total fns)"
  println(s"[+] [$entryType] $label -> ${entry.fullName} ($total fns) -> $outFile")
}

def emitUnresolved(entryType: String, label: String, raw: String): Unit = {
  manifest += s"UNRESOLVED [$entryType]: $label -> $raw"
  println(s"[!] UNRESOLVED [$entryType]: $label -> $raw")
}
