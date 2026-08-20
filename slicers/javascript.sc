// javascript.sc  — JavaScript / TypeScript (Node.js) entry-surface passes.
//
// Concatenated after _prelude.sc (which provides cpg, emit, emitUnresolved,
// collectCallees, sourceWindow, isSkipped, getMethodSource, manifest, ...).
//
// Frontend: jssrc2cpg (handles BOTH .js and .ts — one fragment serves both).
//
// Entry-type taxonomy (run highest-signal first so emit()'s dedupe keeps the
// most informative type):
//   ROUTE_DECORATED — NestJS / routing-controllers: @Get/@Post/... handler methods
//                     (class-level @Controller('prefix') path composed in)
//   ROUTE_HTTP      — Express/Connect/Koa/Fastify/Restify route registrations:
//                     (app|router|server|fastify).get|post|...(path, ...handlers)
//                     and the object form .route({ method, url/path, handler })
//   HANDLER_EXPORT  — file-convention handlers: Next.js API routes (pages/api,
//                     app/**/route.ts) and the exported request handler functions
//   CONTROLLER      — public methods of *Controller / @Controller classes missed above
//   INPUT_SOURCE    — any function reading req/request/ctx/event request data
//                     (req.query/body/params/cookies/headers, ctx.query, event.*)
//
// CALL-GRAPH CAVEAT: jssrc2cpg resolves far fewer CALL->METHOD edges than php2cpg
// (user-function calls with no clear receiver frequently don't resolve), so
// collectCallees is thin and slices are often shallow — the entry function body
// is the primary evidence. A thin slice is NOT evidence of safety. We flag this
// in the manifest header and always emit the entry regardless of callee count.
//
// AUTH CAVEAT (for the triage skill): Node web auth is overwhelmingly enforced in
// MIDDLEWARE that does not appear in a handler's slice — Express `app.use(authMw)`
// / per-route middleware args, Passport strategies, NestJS Guards (@UseGuards),
// Fastify hooks/preHandler. A handler with no in-body auth check is therefore NOT
// necessarily unauthenticated — analogous to a Rails before_action.

// Header note (sits in the manifest's comment block, before any OK lines).
manifest += "# Resolution: jssrc2cpg (JS/TS; call-graph sparse — downstream may be incomplete, a thin slice is NOT evidence of safety). " +
            "Auth is typically Express/Koa middleware or a NestJS Guard OUT of the slice — assess that separately."

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// Simple class name of a method's declaring TypeDecl (jssrc2cpg names controllers
// plainly, e.g. "CatsController"; it also emits spurious per-function TypeDecls,
// which we never query by a *Controller pattern so they don't interfere).
def declClassJs(m: Method): String = m.typeDecl.name.headOption.getOrElse("")

// First quoted string inside a decorator's source text, e.g. @Get(':id') -> ":id",
// @Controller('cats') -> "cats". jssrc2cpg leaves the decorator args in
// Annotation.code (astChildren is empty), so we parse the code text.
def decoratorFirstString(a: nodes.Annotation): Option[String] =
  """['"]([^'"]*)['"]""".r.findFirstMatchIn(a.code).map(_.group(1))

// Path declared by a named decorator on a method or its class.
def decoratorPathOf(anns: Iterator[nodes.Annotation], names: Set[String]): Option[String] =
  anns.toList.find(a => names.contains(a.name)).flatMap(decoratorFirstString)

// Join a class-level path prefix and a method sub-path into one URL pattern.
def joinPathJs(prefix: String, sub: String): String = {
  val p = if (prefix == null) "" else prefix.trim
  val s = if (sub == null) "" else sub.trim
  val joined = ("/" + p.stripPrefix("/").stripSuffix("/") + "/" + s.stripPrefix("/")).replaceAll("/+", "/")
  if (joined.isEmpty) "/" else joined.stripSuffix("/") match { case "" => "/"; case x => x }
}

// Strip the quotes off a string-literal node's code.
def litText(code: String): String =
  code.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'")

// A route registration's path is a string literal that starts with "/" (Express,
// Koa, Fastify, Restify all use leading-slash paths; ":param"/"*"/regex variants
// still begin at "/"). The verb names (get/post/...) are far too common to match
// on alone, so every ROUTE_HTTP match is gated on this — same discipline as the
// PHP/Ruby micro-framework passes.
def looksLikeRoutePath(arg: nodes.Expression): Boolean =
  arg.isLiteral && arg.code.matches("""(?s)['"]/.*['"]""")

// Resolve a route handler argument to concrete Methods: an inline closure
// (arrow/function expression lowered to a MethodRef) or a bare identifier
// referencing a named function. Returns (description, method) pairs.
def resolveJsHandler(arg: nodes.Expression): List[(String, Method)] = {
  val refs = arg.ast.isMethodRef.referencedMethod.filterNot(_.isExternal).l
  if (refs.nonEmpty) refs.map(m => ("closure", m))
  else if (arg.label == "IDENTIFIER")
    cpg.method.nameExact(arg.code).filterNot(_.isExternal).l.map(m => (arg.code, m))
  else Nil
}

// jssrc2cpg models `app.get(...)` with argument(0) = the receiver ("app"),
// argument(1) = first real arg (the path), argument(2..) = the handler chain
// (middleware + final handler). Reads request data off any of these objects.
val JS_REQ_OBJ   = "req|request|ctx|context|event|koaCtx"
val JS_REQ_FIELD = "query|body|params|cookies|headers|header|rawBody|files|file|" +
                   "queryStringParameters|multiValueQueryStringParameters|pathParameters|" +
                   "url|originalUrl|hostname|ip|signedCookies|get|param|fields"
def readsRequestInputJs(m: Method): Boolean = {
  // req.query / ctx.query.name / event.queryStringParameters / req.headers['x'] all
  // lower to <operator>.fieldAccess (and indexAccess) calls whose CODE carries the
  // receiver.field text — matching the call code is the reliable detector.
  lazy val byField = m.ast.isCall.code(s"(?s).*\\b($JS_REQ_OBJ)\\.($JS_REQ_FIELD)\\b.*").nonEmpty
  // req.get('X-Header') / request.header('x') accessor calls.
  lazy val byAccessor = m.ast.isCall.code(s"(?s).*\\b($JS_REQ_OBJ)\\.(get|header|param)\\s*\\(.*").nonEmpty
  byField || byAccessor
}

// ===========================================================================
// ROUTE_DECORATED: NestJS / routing-controllers / tsoa decorators
//   @Get(':id') / @Post() / @Put() / @Delete() / @Patch() / @All() / @Options()
//   on a controller method, with the class-level @Controller('prefix') path.
// ===========================================================================
println("=" * 70)
println("[*] ROUTE_DECORATED: NestJS @Get/@Post/... decorated handlers")
println("=" * 70)

val JS_HTTP_DECORATORS = Set("Get","Post","Put","Delete","Patch","All","Options","Head")

val decoratedHandlers = cpg.method
  .where(_.annotation.name(JS_HTTP_DECORATORS.toSeq: _*))
  .filterNot(_.isExternal)
  .filterNot(m => isSkipped(m.filename))
  .l
println(s"[*] Found ${decoratedHandlers.size} decorated handler method(s)")

decoratedHandlers.foreach { m =>
  val cls       = declClassJs(m)
  val methodAnn = m.annotation.l.find(a => JS_HTTP_DECORATORS.contains(a.name))
  val verb      = methodAnn.map(_.name.toUpperCase).getOrElse("ANY")
  val subPath   = methodAnn.flatMap(decoratorFirstString).getOrElse("")
  val classPath = decoratorPathOf(m.typeDecl.annotation, Set("Controller")).getOrElse("")
  val url       = joinPathJs(classPath, subPath)
  val label     = s"$verb $url"
  emit("ROUTE_DECORATED", label, s"$cls#${m.name}", m, Seq(
    "Routing" -> s"decorator @${methodAnn.map(_.name).getOrElse("?")} ($verb $url)",
    "Class"   -> (if (cls.isEmpty) "?" else cls)
  ))
}
println()

// ===========================================================================
// ROUTE_HTTP: Express / Connect / Koa / Fastify / Restify route registrations
//   (app|router|server|fastify|<id>).get|post|put|patch|delete|options|head|all|use(
//        path, ...middleware, handler)
//   plus the object form  .route({ method, url|path, handler })  (Fastify/Hapi).
// Handler chain = every argument after the path (middleware are surface too — an
// auth middleware that is itself buggy, or a body parser feeding a sink). We slice
// each resolvable function in the chain.
// ===========================================================================
println("=" * 70)
println("[*] ROUTE_HTTP: Express/Koa/Fastify (app|router).get/post/... handlers")
println("=" * 70)

val jsVerbs = "get|post|put|patch|delete|options|head|all|use"
val httpRouteCalls = cpg.call
  .name(jsVerbs)
  .filter(c => Try(looksLikeRoutePath(c.argument(1))).getOrElse(false))
  .filterNot(c => isSkipped(c.method.filename))
  .l
println(s"[*] Found ${httpRouteCalls.size} HTTP route registration(s)")

httpRouteCalls.foreach { call =>
  val verb = call.name.toUpperCase
  val path = Try(litText(call.argument(1).code)).getOrElse("?")
  val label = s"$verb $path"
  // handlers = every argument after the path (argumentIndex >= 2)
  val handlerArgs = call.argument.filter(_.argumentIndex >= 2).l
  val resolved = handlerArgs.flatMap(resolveJsHandler)
  if (resolved.isEmpty)
    emitUnresolved("ROUTE_HTTP", label, handlerArgs.map(_.code.take(40)).mkString(", ") match {
      case "" => "<no handler arg>"; case s => s
    })
  else resolved.foreach { case (desc, m) =>
    emit("ROUTE_HTTP", label, desc, m, Seq("Routing" -> s"express/koa ${call.name}('$path', ...)"))
  }
}
println()

// Object form: fastify.route({method:'GET', url:'/x', handler: fn}) / Hapi server.route(...)
val routeObjCalls = cpg.call
  .nameExact("route")
  .filter(c => c.code.matches("(?s).*\\bhandler\\b.*") && c.code.matches("(?s).*\\b(method|url|path)\\b.*"))
  .filterNot(c => isSkipped(c.method.filename))
  .l
if (routeObjCalls.nonEmpty) println(s"[*] Found ${routeObjCalls.size} object-form .route({...}) registration(s)")
routeObjCalls.foreach { call =>
  val code   = call.code
  val verb   = """method\s*:\s*['"]([A-Za-z]+)['"]""".r.findFirstMatchIn(code).map(_.group(1).toUpperCase).getOrElse("ANY")
  val path   = """(?:url|path)\s*:\s*['"]([^'"]+)['"]""".r.findFirstMatchIn(code).map(_.group(1)).getOrElse("?")
  val label  = s"$verb $path"
  val refs   = call.ast.isMethodRef.referencedMethod.filterNot(_.isExternal).l
  if (refs.isEmpty) emitUnresolved("ROUTE_HTTP", label, s"route({...}) handler not resolvable: ${code.take(80)}")
  else refs.foreach(m => emit("ROUTE_HTTP", label, "handler", m, Seq("Routing" -> s"object-form route ($verb $path)")))
}
if (routeObjCalls.nonEmpty) println()

// ===========================================================================
// HANDLER_EXPORT: file-convention handlers (Next.js API routes & app router).
//   Next.js: pages/api/**.{js,ts} exports a default handler; app/**/route.{js,ts}
//   exports named GET/POST/... functions. These are URL-addressable by file path
//   with no explicit route registration.
// We surface the request-handling functions defined in those files (excluding the
// module-level :program wrapper, ctor/operator nodes).
// ===========================================================================
println("=" * 70)
println("[*] HANDLER_EXPORT: Next.js API routes (pages/api, app/**/route)")
println("=" * 70)

// File is a Next.js API/route module.
def isApiRouteFile(f: String): Boolean =
  f != null && (f.matches("(?s).*/(pages|src/pages)/api/.*\\.(js|ts|mjs|cjs)$") ||
                f.matches("(?s).*/(app|src/app)/.*/route\\.(js|ts|mjs|cjs)$") ||
                f.matches("(?s)(pages|src/pages)/api/.*\\.(js|ts|mjs|cjs)$") ||
                f.matches("(?s)(app|src/app)/.*/route\\.(js|ts|mjs|cjs)$"))

val handlerMethods = cpg.method
  .filterNot(_.isExternal)
  .filterNot(m => isSkipped(m.filename))
  .filter(m => isApiRouteFile(m.filename))
  .nameNot(":program", "<operator>.*", "<init>", "<clinit>")
  .l
println(s"[*] Found ${handlerMethods.size} function(s) in API-route files")

handlerMethods.foreach { m =>
  val label = s"${m.filename}#${m.name}"
  emit("HANDLER_EXPORT", label, m.name, m, Seq(
    "Routing" -> "next.js file-convention handler (URL = file path)",
    "File"    -> m.filename
  ))
}
println()

// ===========================================================================
// CONTROLLER: public methods of *Controller / @Controller classes missed by the
// route passes (handlers without a per-method decorator, convention controllers).
// jssrc2cpg does not reliably populate method visibility, so we emit all real
// methods (excluding ctor/operator/lambda) and note it. emit() dedupe drops
// anything already sliced as a ROUTE_*.
// ===========================================================================
println("=" * 70)
println("[*] CONTROLLER: *Controller / @Controller class methods")
println("=" * 70)

// NB: jssrc2cpg emits a spurious TypeDecl for every function/lambda (e.g. a
// function `namedHandler` yields a TypeDecl named `namedHandler`), so matching a
// TypeDecl *name* suffix alone would wrongly pull in functions. Gate on the
// TypeDecl being a real class — it has a synthesized `<init>` member — OR carrying
// a controller decorator. (Also why we don't use a `*Handler$` suffix here.)
def isRealClass(t: TypeDecl): Boolean = t.method.nameExact("<init>").nonEmpty
val controllerTypes = cpg.typeDecl
  .filterNot(_.isExternal)
  .filterNot(t => isSkipped(t.filename))
  .filter(t => (isRealClass(t) && t.name.matches(".*(Controller|Resource)$")) ||
               t.annotation.name.exists(n => Set("Controller","JsonController").contains(n)))
  .l
println(s"[*] Found ${controllerTypes.size} controller-ish class(es)")

val ctrlMethods = controllerTypes.method
  .nameNot(":program", "<init>", "<clinit>", "<lambda>.*", ".*<lambda>.*", "<operator>.*")
  .filterNot(_.isExternal)
  .l
println(s"[*] ${ctrlMethods.size} method(s) on controller-ish classes (pre-dedupe)")

ctrlMethods.foreach { m =>
  val cls   = declClassJs(m)
  val label = s"$cls#${m.name}"
  emit("CONTROLLER", label, label, m, Seq(
    "Class"   -> (if (cls.isEmpty) "?" else cls),
    "Routing" -> "convention/decorated controller method (visibility not enforced by frontend)"
  ))
}
println()

// ===========================================================================
// INPUT_SOURCE: framework-agnostic safety net — any function reading request data
// off req/request/ctx/event (Express/Koa/serverless). Catches custom dispatchers,
// helpers, and serverless handlers (exports.handler) the passes above miss.
// emit() dedupe skips anything already sliced.
// ===========================================================================
println("=" * 70)
println("[*] INPUT_SOURCE: functions reading req/ctx/event request data")
println("=" * 70)

val inputMethods = cpg.method
  .nameNot(":program", "<operator>.*", "<init>", "<clinit>", "<lambda>.*::<.*")
  .filterNot(_.isExternal)
  .filterNot(m => isSkipped(m.filename))
  .filter(readsRequestInputJs)
  .l
println(s"[*] Found ${inputMethods.size} function(s) reading request input directly")

inputMethods.foreach { m =>
  val cls   = declClassJs(m)
  val label = if (cls.nonEmpty && cls != ":program") s"$cls#${m.name}" else s"${m.filename}#${m.name}"
  emit("INPUT_SOURCE", label, label, m, Seq("Reads" -> "req/request/ctx/event request data"))
}
println()
