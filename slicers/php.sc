// php.sc  — PHP-specific entry-surface passes.
//
// Concatenated after _prelude.sc (which provides cpg, emit, collectCallees,
// sourceWindow, parseBlockCallback, isSkipped, getMethodSource, ...).
//
// Finds visitor-accessible (unauthenticated remote) attack surface in *generic*
// PHP applications (NOT WordPress-specific) via five framework-agnostic passes,
// run highest-signal first so emit()'s dedupe keeps the most informative type:
//   TYPE 1 SCRIPT       — directly-requestable .php file top-level (<global>) code
//   TYPE 2 ROUTE        — Laravel / Lumen routes
//   TYPE 3 ROUTE        — micro-framework routes (Slim/Silex/FastRoute/Klein)
//   TYPE 4 CONTROLLER   — *Controller public methods + #[Route]/@Route actions
//   TYPE 5 INPUT_SOURCE — any function reading a request superglobal / filter_input

// ---------------------------------------------------------------------------
// PHP callback resolution (callbacks living inside arrays / strings)
// ---------------------------------------------------------------------------

// Resolve a callback by its various textual spellings to concrete Methods:
//   "Class@method" (Laravel) | "Class:method" (Slim) | "Class::method" |
//   "function_name". Falls back to a fuzzy method-name lookup if the class
//   can't be matched (php2cpg sometimes namespaces TypeDecls).
def resolveByName(raw: String): List[(String, Method)] = {
  val name = raw.trim.stripPrefix("\\")
  val sep  = List("@", "::", ":").find(name.contains)
  sep match {
    case Some(s) =>
      val parts = name.split(java.util.regex.Pattern.quote(s), 2)
      val cls   = parts(0).split("\\\\").last      // strip namespace
      val meth  = parts(1)
      val r = cpg.method.nameExact(meth).where(_.typeDecl.name(s".*\\b$cls$$|$cls")).l
      if (r.nonEmpty) r.map(m => (s"$cls::$meth", m))
      else cpg.method.nameExact(meth).l.map(m => (s"$cls::$meth (fuzzy)", m))
    case None =>
      cpg.method.nameExact(name).l.map(m => (name, m))
  }
}

// Resolve a route/registration callback argument to concrete Methods, trying,
// in order: a closure (MethodRef), an array form [$obj,'m'] (BLOCK), a string
// literal "Class@method"/"function", and finally any 'uses' string in the
// surrounding source window (Laravel array-route style).
def resolveHandlerArg(call: Call, argIdx: Int): List[(String, Method)] = {
  val argOpt = Try(call.argument(argIdx)).toOption
  argOpt match {
    case None => Nil
    case Some(arg) =>
      // 1) closure passed inline -> MethodRef -> referenced Method
      val refMethods = arg.ast.isMethodRef.referencedMethod.l
      if (refMethods.nonEmpty) refMethods.map(m => ("closure", m))
      else arg.label match {
        case "BLOCK" =>
          parseBlockCallback(arg) match {
            case Some((cls, meth)) if cls.nonEmpty =>
              val r = cpg.method.nameExact(meth).where(_.typeDecl.nameExact(cls)).l
              if (r.nonEmpty) r.map(m => (s"$cls::$meth", m))
              else cpg.method.nameExact(meth).l.map(m => (s"$cls::$meth (fuzzy)", m))
            case Some(("", meth)) => cpg.method.nameExact(meth).l.map(m => (meth, m))
            case None             => Nil
          }
        case "LITERAL" =>
          val s = arg.code.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'")
          resolveByName(s)
        case _ =>
          // array(['uses' => 'Class@method']) or other forms — scan source text
          val win = sourceWindow(call)
          val usesPat = """['"]([A-Za-z_\\][\w\\]*(?:@|::)\w+)['"]""".r
          usesPat.findFirstMatchIn(win).map(_.group(1)).toList.flatMap(resolveByName)
      }
  }
}

// Request superglobals = the canonical taint sources for any PHP request.
val SUPERGLOBALS = Set("_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER", "_ENV", "HTTP_RAW_POST_DATA")

// Does this method read request input directly (superglobal / filter_input / php://input)?
def readsRequestInputPhp(m: Method): Boolean = {
  val hasSuperglobal = m.ast.isIdentifier.name(SUPERGLOBALS.toSeq: _*).nonEmpty
  lazy val hasFilterInput = m.ast.isCall.nameExact("filter_input", "filter_input_array",
    "apache_request_headers", "getallheaders").nonEmpty
  lazy val hasPhpInput = m.ast.isLiteral.code(".*php://input.*").nonEmpty
  hasSuperglobal || hasFilterInput || hasPhpInput
}

// ===========================================================================
// TYPE 1: Directly-requestable scripts (file-level <global> code)
//
// In a plain PHP app, every .php file under the web root is reachable by URL,
// and its top-level code executes on request. We surface the <global> methods
// that actually consume request input at file scope (or via their immediate
// callees) — these are the classic "drop a script, hit it directly" entries.
// ===========================================================================
println("=" * 70)
println("[*] TYPE 1: Directly-requestable scripts (<global> file code)")
println("=" * 70)

val globals = cpg.method.nameExact("<global>").filterNot(m => isSkipped(m.filename)).l
println(s"[*] Found ${globals.size} file-level <global> method(s)")

globals.foreach { g =>
  val directInput   = readsRequestInputPhp(g)
  // also catch the very common "front controller includes the real handler" shape
  val calleeInput   = g.callee.filterNot(_.isExternal).nameNot("<operator>.*").exists(readsRequestInputPhp)
  if (directInput || calleeInput) {
    val label = g.filename
    val why   = if (directInput) "reads request input at file scope" else "dispatches to input-reading code"
    emit("SCRIPT", label, "<file top-level>", g, Seq("Reason" -> why))
  }
}
println()

// ===========================================================================
// TYPE 2: Laravel / Lumen routes
//   Route::get|post|put|patch|delete|options|any|match|resource|apiResource|
//          fallback|view|redirect(...)  and  $router->...(), $route->...()
// The action is the 2nd argument: a closure, 'Controller@method', or
// [Controller::class, 'method'], or an array with a 'uses' key.
// ===========================================================================
println("=" * 70)
println("[*] TYPE 2: Laravel / Lumen routes (Route::verb / $router->verb)")
println("=" * 70)

val laravelVerbs = "get|post|put|patch|delete|options|any|match|resource|apiResource|fallback|view|redirect|permanentRedirect"
val laravelCalls = cpg.call
  .name(laravelVerbs)
  .filter(c => c.code.matches(s"""(?s)(Route|\\$$router|\\$$route)\\s*(::|->)\\s*($laravelVerbs)\\b.*"""))
  .filterNot(c => isSkipped(c.method.filename))
  .l
println(s"[*] Found ${laravelCalls.size} Laravel-style route registration(s)")

laravelCalls.foreach { call =>
  val verb = call.name
  val path = Try(call.argument(1).code.stripPrefix("\"").stripSuffix("\"")
                                      .stripPrefix("'").stripSuffix("'")).getOrElse("?")
  val label = s"$verb $path"
  // resource/apiResource take a controller class name as the action (all public methods exposed)
  if (verb == "resource" || verb == "apiResource") {
    val ctrl = Try(call.argument(2).code.replaceAll("""['"]""", "").replaceAll("""::class$""", "")).getOrElse("")
    val cls  = ctrl.split("\\\\").last
    val actions = cpg.method.where(_.typeDecl.name(s".*\\b$cls$$|$cls")).isPublic.nameNot("__construct", "<global>").l
    if (actions.isEmpty) emitUnresolved("ROUTE", label, s"resource controller '$ctrl' not found")
    else actions.foreach(m => emit("ROUTE", s"$label#${m.name}", s"$cls::${m.name}", m))
  } else {
    resolveHandlerArg(call, 2) match {
      case Nil     => emitUnresolved("ROUTE", label, Try(call.argument(2).code).getOrElse("<no arg>"))
      case entries => entries.foreach { case (desc, m) => emit("ROUTE", label, desc, m) }
    }
  }
}
println()

// ===========================================================================
// TYPE 3: Micro-framework routes
//   Slim/Silex:  $app->get|post|put|patch|delete|options|any|map(path, handler)
//   FastRoute:   $r->addRoute(method, path, handler)
//   Klein:       $klein->respond(path, handler)
// Handler is a closure, 'Class:method'/'Class@method', or [Class, 'method'].
// (We exclude the Laravel spellings already handled in TYPE 2.)
// ===========================================================================
println("=" * 70)
println("[*] TYPE 3: Micro-framework routes (Slim/Silex/FastRoute/Klein)")
println("=" * 70)

// Verbs like get/post/delete are extremely common method names, so matching on
// the verb alone is hopelessly noisy ($wpdb->delete(), $obj->get(), ...). The
// reliable discriminator is the FIRST argument: a route registration's path is
// a string literal starting with "/" (or containing a {placeholder}). We gate
// every micro-framework match on that.
def looksLikePath(arg: nodes.Expression): Boolean = arg.isLiteral &&
  arg.code.matches("""(?s)['"](/.*|\{.*)['"]""")

val microVerbs = "get|post|put|patch|delete|options|head|any|map"
val microCalls = cpg.call
  .name(s"$microVerbs|addRoute|respond")
  .filter { c =>
    val code = c.code
    val isMicro =
      (code.matches(s"""(?s)\\$$\\w+\\s*->\\s*($microVerbs)\\s*\\(.*""") ||
       code.matches("""(?s).*->\s*addRoute\s*\(.*""") ||
       code.matches("""(?s).*->\s*respond\s*\(.*""")) &&
      !code.matches("""(?s)(Route|\$router|\$route)\s*(::|->).*""")   // not a Laravel route
    // path is arg 2 for addRoute(method, path, handler), arg 1 otherwise
    val pathIdx = if (c.name == "addRoute") 2 else 1
    isMicro && Try(looksLikePath(c.argument(pathIdx))).getOrElse(false)
  }
  .filterNot(c => isSkipped(c.method.filename))
  .l
println(s"[*] Found ${microCalls.size} micro-framework route registration(s)")

microCalls.foreach { call =>
  val verb = call.name
  // For addRoute(method, path, handler) the handler is arg 3; otherwise arg 2.
  val handlerIdx = if (verb == "addRoute") 3 else 2
  val path = Try {
    val pIdx = if (verb == "addRoute") 2 else 1
    call.argument(pIdx).code.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'")
  }.getOrElse("?")
  val label = s"$verb $path"
  resolveHandlerArg(call, handlerIdx) match {
    case Nil     => emitUnresolved("ROUTE", label, Try(call.argument(handlerIdx).code).getOrElse("<no arg>"))
    case entries => entries.foreach { case (desc, m) => emit("ROUTE", label, desc, m) }
  }
}
println()

// ===========================================================================
// TYPE 4: Controllers
//   (a) Symfony attribute/annotation routes: methods preceded by #[Route(...)]
//       or @Route(...) in source — directly mapped HTTP actions.
//   (b) Convention controllers: classes named *Controller — their public,
//       non-magic methods are the framework-dispatched actions (CodeIgniter,
//       CakePHP, Symfony, Laravel single-action/__invoke, etc.).
// ===========================================================================
println("=" * 70)
println("[*] TYPE 4: Controllers (#[Route] actions + *Controller classes)")
println("=" * 70)

// (a) Symfony #[Route] / @Route annotated methods (detect from source text just
//     above each public method in controller-ish files).
def hasRouteAnnotation(m: Method): Boolean = {
  val start = m.lineNumber.getOrElse(0)
  if (start <= 1) return false
  val fullPath = new File(sourceRoot, m.filename).getPath
  Try {
    Using.resource(Source.fromFile(fullPath)) { src =>
      val lines = src.getLines().toArray
      // Look at the ~6 lines preceding the method AND its reported start line:
      // php2cpg points a method's lineNumber at its #[Attribute], so the Route
      // attribute can sit on `start` itself, not only above it.
      val from = math.max(0, start - 7)
      lines.slice(from, start).exists(l => l.contains("#[Route") || l.contains("@Route"))
    }
  }.getOrElse(false)
}

val controllerMethods = cpg.typeDecl
  .name(".*Controller$")
  .filterNot(t => isSkipped(t.filename))
  .method
  .isPublic
  .nameNot("__construct", "__destruct", "__invoke", "<global>", "<clinit>", ".*::<.*")
  .nameNot("<operator>.*")
  .l
println(s"[*] Found ${controllerMethods.size} public method(s) on *Controller classes")

controllerMethods.foreach { m =>
  val cls   = m.typeDecl.name.headOption.getOrElse("?")
  val annotated = hasRouteAnnotation(m)
  val label = s"$cls::${m.name}"
  val extra = if (annotated) Seq("Routing" -> "#[Route]/@Route annotated") else Seq("Routing" -> "convention (*Controller public method)")
  emit("CONTROLLER", label, label, m, extra)
}

// Also catch #[Route]/@Route annotated public methods on classes NOT named *Controller.
val annotatedElsewhere = cpg.method.isPublic
  .nameNot("__construct", "__destruct", "<global>", "<clinit>")
  .nameNot("<operator>.*")
  .filterNot(m => isSkipped(m.filename))
  .filterNot(m => m.typeDecl.name(".*Controller$").nonEmpty)
  .filter(hasRouteAnnotation)
  .l
annotatedElsewhere.foreach { m =>
  val cls = m.typeDecl.name.headOption.getOrElse("")
  emit("CONTROLLER", s"$cls::${m.name}", s"$cls::${m.name}", m, Seq("Routing" -> "#[Route]/@Route annotated"))
}
println()

// ===========================================================================
// TYPE 5: Request-input sources (framework-agnostic safety net)
//
// ANY function that reads a request superglobal, filter_input(), or php://input
// is by definition reachable with attacker-controlled data. This catches custom
// routers, dispatcher patterns, and helpers the framework heuristics above miss.
// Entries already sliced under TYPES 1-4 are skipped by the emit() dedupe.
// ===========================================================================
println("=" * 70)
println("[*] TYPE 5: Request-input sources ($_GET/$_POST/... / filter_input)")
println("=" * 70)

val inputMethods = cpg.method
  .nameNot("<global>", "<operator>.*")        // file-scope handled in TYPE 1
  .filterNot(_.isExternal)
  .filterNot(m => isSkipped(m.filename))
  .filter(readsRequestInputPhp)
  .l
println(s"[*] Found ${inputMethods.size} function(s) reading request input directly")

inputMethods.foreach { m =>
  val cls   = Try(m.typeDecl.name.headOption.getOrElse("")).getOrElse("")
  val label = if (cls.nonEmpty && cls != "<global>") s"$cls::${m.name}" else m.name
  val sgs   = m.ast.isIdentifier.name(SUPERGLOBALS.toSeq: _*).name.distinct.l.mkString(",")
  val src   = if (sgs.nonEmpty) sgs else "filter_input/php://input"
  emit("INPUT_SOURCE", label, label, m, Seq("Reads" -> src))
}
println()
