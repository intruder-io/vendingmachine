// ruby.sc  — Ruby (Rails + Sinatra) entry-surface passes.
//
// Concatenated after _prelude.sc (which provides cpg, emit, emitUnresolved,
// collectCallees, sourceWindow, isSkipped, getMethodSource, manifest, ...).
//
// Entry-type taxonomy (run highest-signal first so emit()'s dedupe keeps the
// most informative type):
//   ROUTE_RAILS  — config/routes.rb DSL resolved to a controller#action
//   ROUTE_MICRO  — Sinatra/Rack  `verb '/path' do ... end`  block handlers
//   CONTROLLER   — public instance methods of *Controller classes
//   INPUT_SOURCE — any method reading params/cookies/session/request.*
//
// There is NO "SCRIPT" type for Ruby: .rb files are not URL-addressable the way
// .php files are. The file-level method here is `<main>` (NOT `<global>`).
//
// rubysrc2cpg resolves far fewer CALL->METHOD edges than php2cpg, so
// collectCallees is thin and slices are often shallow. We always emit the entry
// regardless of how many callees resolve, and flag the limitation up front so a
// thin slice is not mistaken for "safe".

// Header note (sits in the manifest's comment block, before any OK lines).
manifest += "# Resolution: rubysrc2cpg (call-graph sparse; downstream may be incomplete — a thin slice is NOT evidence of safety)"

// ---------------------------------------------------------------------------
// Ruby helpers
// ---------------------------------------------------------------------------

// snake_case (single path segment) -> CamelCase. "user_sessions" -> "UserSessions".
def camelizeSeg(s: String): String =
  s.split("_").filter(_.nonEmpty).map(p => p.head.toUpper + p.tail).mkString

// Pull a symbol list for a Rails route keyword from raw source, e.g.
//   only: [:index, :show]   -> List("index","show")
//   except: :destroy        -> List("destroy")
def symList(code: String, kw: String): List[String] = {
  val bracket = s"""$kw:\\s*\\[([^\\]]*)\\]""".r.findFirstMatchIn(code).map(_.group(1))
  bracket match {
    case Some(inside) => """:(\w+)""".r.findAllMatchIn(inside).map(_.group(1)).toList
    case None         => s"""$kw:\\s*:(\\w+)""".r.findFirstMatchIn(code).map(_.group(1)).toList
  }
}

// Find a "controller#action" target inside a route call's source code,
// covering `to: 'c#a'`, `=> 'c#a'`, and the positional `root 'c#a'` forms.
def railsTarget(code: String): Option[String] =
  """['"]([A-Za-z0-9_/]+#[A-Za-z0-9_]+)['"]""".r.findFirstMatchIn(code).map(_.group(1))

// Resolve a "controller#action" string (namespaced `admin/users#index` OK) to
// concrete Methods and emit them. The primary match keys on the simple
// controller class name as a suffix (so `Admin::UsersController` still matches
// `.*\bUsersController$`); a stem-scoped fuzzy fallback covers odd namespacing.
def emitRailsAction(target: String, label: String, routing: String): Unit = {
  val parts = target.split("#", 2)
  if (parts.length != 2 || parts(1).isEmpty) { emitUnresolved("ROUTE_RAILS", label, s"unparseable target '$target'"); return }
  val action = parts(1)
  val segs   = parts(0).split("/").filter(_.nonEmpty)
  val stem   = segs.lastOption.map(camelizeSeg).getOrElse("")
  val simple = stem + "Controller"
  val primary = cpg.method.nameExact(action).where(_.typeDecl.name(s".*\\b$simple$$|$simple")).l
  if (primary.nonEmpty) {
    primary.foreach(m => emit("ROUTE_RAILS", label, s"$simple#$action", m, Seq("Routing" -> routing)))
  } else {
    // stem-scoped fuzzy: action on any *Controller whose name contains the stem
    val fuzzy = if (stem.nonEmpty) cpg.method.nameExact(action).where(_.typeDecl.name(s".*$stem.*Controller$$")).l else Nil
    if (fuzzy.nonEmpty) fuzzy.foreach(m => emit("ROUTE_RAILS", label, s"$simple#$action (fuzzy)", m, Seq("Routing" -> s"$routing; fuzzy class match")))
    else emitUnresolved("ROUTE_RAILS", label, s"$simple#$action not found")
  }
}

// Expand `resources :x` / `resource :x` into the RESTful action set and emit
// each that resolves on the conventional controller. Namespace prefixing from
// an enclosing `namespace`/`scope` block is best-effort (not tracked in the CPG).
def emitRailsResource(sym: String, singular: Boolean, code: String, label: String): Unit = {
  if (sym.isEmpty) { emitUnresolved("ROUTE_RAILS", label, "resource with no symbol arg"); return }
  val baseActions = if (singular) Seq("show", "new", "create", "edit", "update", "destroy")
                    else          Seq("index", "show", "new", "create", "edit", "update", "destroy")
  val only   = symList(code, "only")
  val except = symList(code, "except")
  val actions = if (only.nonEmpty)        baseActions.filter(only.contains)
                else if (except.nonEmpty) baseActions.filterNot(except.contains)
                else                      baseActions
  val stem   = camelizeSeg(sym)
  // controller is conventionally the pluralized form; try the symbol as-is and a
  // naive +"s" plural (covers `resource :session` -> SessionsController).
  val candRe = Set(stem + "Controller", stem + "sController").map(c => s".*\\b$c$$").mkString("|")
  val found  = cpg.method.where(_.typeDecl.name(candRe)).nameExact(actions: _*).l
  if (found.isEmpty) emitUnresolved("ROUTE_RAILS", label, s"resource '$sym' (${stem}Controller / ${stem}sController) not found")
  else found.foreach(m => emit("ROUTE_RAILS", s"$label#${m.name}", s"${stem}Controller#${m.name}", m,
                            Seq("Routing" -> "rails-resource (namespace best-effort)")))
}

// ===========================================================================
// ROUTE_RAILS: config/routes.rb DSL
// ===========================================================================
println("=" * 70)
println("[*] ROUTE_RAILS: config/routes.rb route registrations")
println("=" * 70)

val routeCalls = cpg.call
  .name("get|post|put|patch|delete|match|root|resources|resource|mount|devise_for")
  .filter(_.method.filename.contains("config/routes"))
  .l
println(s"[*] Found ${routeCalls.size} Rails route call(s) in config/routes")

routeCalls.foreach { call =>
  val verb = call.name
  val code = call.code
  verb match {
    case "resources" | "resource" =>
      val sym = Try(call.argument(1).code.trim.stripPrefix(":").replaceAll("""['"]""", "")).getOrElse("")
      emitRailsResource(sym, singular = verb == "resource", code, s"$verb :$sym")

    case "mount" =>
      emitUnresolved("ROUTE_RAILS", "mount", s"engine/rack app mounted (routes external to this tree): ${code.take(120)}")

    case "devise_for" =>
      emitUnresolved("ROUTE_RAILS", "devise_for",
        "Devise-generated auth routes (sessions/registrations/passwords); app auth is Devise-based")

    case "root" =>
      railsTarget(code) match {
        case Some(t) => emitRailsAction(t, "root /", "rails-route (root)")
        case None    => emitUnresolved("ROUTE_RAILS", "root /", s"no controller#action in: ${code.take(120)}")
      }

    case _ => // get/post/put/patch/delete/match
      val path = Try(call.argument(1).code.stripPrefix("\"").stripSuffix("\"")
                                          .stripPrefix("'").stripSuffix("'")).getOrElse("?")
      val label = s"$verb $path"
      railsTarget(code) match {
        case Some(t) => emitRailsAction(t, label, "rails-route")
        case None    => emitUnresolved("ROUTE_RAILS", label, s"no controller#action in: ${code.take(120)}")
      }
  }
}
println()

// ===========================================================================
// ROUTE_MICRO: Sinatra / Rack  `verb '/path' do ... end`
//
// Gate on the FIRST argument being a path literal (starts with "/" or has a
// {placeholder}) — the verb names alone are far too common. The handler is the
// trailing block, lowered to a synthetic closure METHOD; reach it via the block
// method-ref, falling back to the nearest method in the same file by line.
// ===========================================================================
println("=" * 70)
println("[*] ROUTE_MICRO: Sinatra/Rack route blocks")
println("=" * 70)

def looksLikePathRuby(arg: nodes.Expression): Boolean = arg.isLiteral &&
  arg.code.matches("""(?s)['"](/.*|\{.*)['"]""")

val microCalls = cpg.call
  .name("get|post|put|patch|delete|options|head")
  .filterNot(_.method.filename.contains("config/routes"))
  .filter(c => Try(looksLikePathRuby(c.argument(1))).getOrElse(false))
  .filterNot(c => isSkipped(c.method.filename))
  .l
println(s"[*] Found ${microCalls.size} micro-framework route block(s)")

microCalls.foreach { call =>
  val verb  = call.name
  val path  = Try(call.argument(1).code.stripPrefix("\"").stripSuffix("\"")
                                       .stripPrefix("'").stripSuffix("'")).getOrElse("?")
  val label = s"$verb $path"
  // 1) block lowered to a closure reachable via MethodRef
  val refMethods = call.ast.isMethodRef.referencedMethod.l
  val handlers =
    if (refMethods.nonEmpty) refMethods
    else {
      // 2) fallback: nearest synthetic closure / method in the same file at/after the call line
      val file = Try(call.method.filename).getOrElse("")
      val cl   = call.lineNumber.getOrElse(-1)
      cpg.method
        .filter(_.filename == file)
        .name(".*(lambda|proc|closure).*")
        .filter(_.lineNumber.exists(ln => ln >= cl && ln <= cl + 2))
        .sortBy(_.lineNumber.getOrElse(Int.MaxValue))
        .l
    }
  if (handlers.nonEmpty) handlers.foreach(m => emit("ROUTE_MICRO", label, "block", m, Seq("Routing" -> "sinatra/rack block")))
  else emitUnresolved("ROUTE_MICRO", label, s"block handler not resolvable: ${call.code.take(120)}")
}
println()

// ===========================================================================
// CONTROLLER: public instance methods of *Controller classes
//
// Ruby `private`/`protected` are runtime calls, not modifiers — rubysrc2cpg does
// NOT reliably populate METHOD visibility. So we derive visibility from source
// text (track the most recent bare private/protected/public above the method,
// plus inline `private def` and `private :sym`), and exclude methods registered
// as before_action/after_action/... callbacks (those are filters, not actions).
// ===========================================================================
println("=" * 70)
println("[*] CONTROLLER: *Controller public action methods")
println("=" * 70)

// Names registered as Rails callbacks anywhere — these are filters, not actions.
// Extract ONLY the callback method symbol (the first `:name` after the verb), not
// the symbols inside `only:`/`except:` lists (so `skip_before_action :x, only: [:index]`
// does not wrongly mark `index` as a callback).
val callbackNames: Set[String] = cpg.call
  .name("before_action|after_action|around_action|prepend_before_action|append_before_action|skip_before_action|before_filter|after_filter|skip_before_filter")
  .code
  .flatMap(c => """_(?:action|filter)\s+:(\w+[!?]?)""".r.findFirstMatchIn(c).map(_.group(1)))
  .toSet

// Source-derived visibility for a controller method: returns true if the method
// is (best-effort) part of the class's PUBLIC section.
def isPublicActionBySource(m: Method): Boolean = {
  val start = m.lineNumber.getOrElse(0)
  if (start <= 0) return true
  val fullPath = new File(sourceRoot, m.filename).getPath
  Try {
    Using.resource(Source.fromFile(fullPath)) { src =>
      val lines = src.getLines().toArray
      val markedNonPublic = scala.collection.mutable.Set[String]()
      var mode = "public"
      val pmList = """^(private|protected|public)\s+(:.+)$""".r
      // track modifier state over the lines ABOVE the method's def line
      var i = 0
      while (i < lines.length && i < start - 1) {
        val t = lines(i).trim
        if      (t == "private")   mode = "private"
        else if (t == "protected") mode = "protected"
        else if (t == "public")    mode = "public"
        else pmList.findFirstMatchIn(t).foreach { mm =>
          if (mm.group(1) != "public")
            """:(\w+)""".r.findAllMatchIn(mm.group(2)).foreach(x => markedNonPublic += x.group(1))
        }
        i += 1
      }
      val ownLine = if (start - 1 >= 0 && start - 1 < lines.length) lines(start - 1).trim else ""
      val inlineNonPublic = ownLine.startsWith("private def") || ownLine.startsWith("protected def")
      (mode == "public") && !inlineNonPublic && !markedNonPublic.contains(m.name)
    }
  }.getOrElse(true)
}

val ctrlMethods = cpg.typeDecl
  .name(".*Controller$")
  .filterNot(t => isSkipped(t.filename))
  .method
  .nameNot("<main>", "<body>", ":program", "<init>", "<clinit>", "initialize")
  .nameNot("<operator>.*", "<lambda>.*", ".*<lambda>.*")
  .l
println(s"[*] Found ${ctrlMethods.size} method(s) on *Controller classes (pre-filter)")

ctrlMethods.foreach { m =>
  val name = m.name
  if (!callbackNames.contains(name) && isPublicActionBySource(m)) {
    val cls   = m.typeDecl.name.headOption.getOrElse("?")
    val label = s"$cls#$name"
    emit("CONTROLLER", label, label, m, Seq("Visibility" -> "public (source-derived)"))
  }
}
println()

// ===========================================================================
// INPUT_SOURCE: any method reading request input (framework-agnostic safety net)
//
// `params`/`cookies`/`session` are method calls (sometimes identifiers), not
// superglobals. request.{params,body,headers,GET,POST,...} are reads off the
// request object. Be liberal — false positives here are cheap (catch-all type).
// Entries already sliced under ROUTE_*/CONTROLLER are skipped by emit() dedupe.
// ===========================================================================
println("=" * 70)
println("[*] INPUT_SOURCE: methods reading params/cookies/session/request.*")
println("=" * 70)

def readsRequestInputRuby(m: Method): Boolean = {
  // params[:x]/cookies[:x]/session[:x] lower to `<operator>.indexAccess` calls whose
  // CODE is "params[:x]" — bare `params` is rarely a standalone node — so matching on
  // the call code is the reliable detector. `\b...\b` avoids matching `user_params`.
  val hasCode = m.ast.isCall.code("(?s).*\\b(params|cookies|session|flash)\\b.*").nonEmpty
  lazy val hasCall = m.ast.isCall.name("params|cookies|session|flash").nonEmpty
  lazy val hasId   = m.ast.isIdentifier.name("params|cookies|session|flash").nonEmpty
  lazy val hasReq  = m.ast.isCall.code(
    "(?s).*\\brequest\\.(params|body|headers|GET|POST|raw_post|query_parameters|request_parameters|env)\\b.*").nonEmpty
  hasCode || hasCall || hasId || hasReq
}

val inputMethods = cpg.method
  .nameNot("<main>", "<body>", ":program", "<operator>.*", "<lambda>.*", ".*<lambda>.*")
  .filterNot(_.isExternal)
  .filterNot(m => isSkipped(m.filename))
  .filter(readsRequestInputRuby)
  .l
println(s"[*] Found ${inputMethods.size} method(s) reading request input directly")

inputMethods.foreach { m =>
  val cls   = Try(m.typeDecl.name.headOption.getOrElse("")).getOrElse("")
  val label = if (cls.nonEmpty && cls != "<main>") s"$cls#${m.name}" else m.name
  emit("INPUT_SOURCE", label, label, m, Seq("Reads" -> "params/cookies/session/request"))
}
println()
