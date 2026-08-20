// java.sc  — Java/JVM entry-surface passes (Spring MVC/WebFlux, JAX-RS, Servlets).
//
// Concatenated after _prelude.sc (which provides cpg, emit, emitUnresolved,
// collectCallees, isSkipped, getMethodSource, manifest, ...).
//
// ONE fragment serves BOTH Java frontends — the CPG queries are identical:
//   * jimple2cpg  (BYTECODE: .jar/.war/.class)  — call graph is well resolved;
//     method bodies render from the Jimple IR (METHOD.code), since `filename`
//     points at a transient extracted .class path (the prelude handles this
//     fallback). This is the high-resolution path.
//   * javasrc2cpg (SOURCE: .java)               — readable source bodies; type
//     resolution good, call graph slightly thinner than bytecode.
// The runner picks the frontend from the input kind (compiled vs source); this
// script auto-detects which CPG it was handed (via .class filenames) only to set
// the manifest's `# Resolution:` note correctly.
//
// Entry-type taxonomy (run highest-signal first so emit()'s dedupe keeps the most
// informative type):
//   ROUTE_SPRING  — @RequestMapping/@GetMapping/.../@PostMapping handler methods
//                   (class-level @RequestMapping path prefix composed in)
//   ROUTE_JAXRS   — @GET/@POST/... methods on @Path resources (class @Path prefix)
//   ROUTE_SERVLET — doGet/doPost/... on HttpServlet subclasses (@WebServlet pattern)
//   CONTROLLER    — public methods of @Controller/@RestController/@Path classes (or
//                   *Controller/*Resource/*Endpoint by convention) missed above
//   INPUT_SOURCE  — methods taking @RequestParam/@PathVariable/@RequestBody/...
//                   (Spring) or @QueryParam/@PathParam/... (JAX-RS), or reading a
//                   (Http)ServletRequest — framework-agnostic safety net
//
// AUTH CAVEAT (for the triage skill): JVM web auth is overwhelmingly enforced
// OUTSIDE the handler — Spring Security `SecurityFilterChain`/`@EnableWebSecurity`
// beans, method-security annotations (`@PreAuthorize`/`@Secured`/`@RolesAllowed`),
// servlet `Filter`s, or web.xml `<security-constraint>`. None of these appear in a
// handler's slice. A handler with no in-body auth check is therefore NOT
// necessarily unauthenticated — analogous to a Rails `before_action`.

// Was this CPG produced from bytecode (jimple2cpg) or source (javasrc2cpg)?
// jimple2cpg sets METHOD.filename to a `.class` path.
val isBytecode = cpg.method.filename(".*\\.class$").nonEmpty
if (isBytecode)
  manifest += "# Resolution: jimple2cpg (bytecode; call graph well-resolved — downstream is trustworthy. " +
              "Method bodies are rendered from the Jimple IR, not Java source. Auth is typically a Spring " +
              "Security filter chain / method-security annotation OUT of the slice — assess that separately)"
else
  manifest += "# Resolution: javasrc2cpg (source; good type resolution, call graph slightly thinner than bytecode. " +
              "Auth is typically a Spring Security filter chain / method-security annotation OUT of the slice)"

// ---------------------------------------------------------------------------
// Annotation helpers
//
// Both frontends expose, on a Method/TypeDecl/Parameter:  .annotation -> Annotation
// with .name (SIMPLE name, e.g. "GetMapping") and .fullName (FQN when known). The
// annotation's argument text lives in its AST children .code, in forms like:
//   value = {"/greet"}    path = {"/admin/wipe"}    value = "/find"   urlPatterns = {"/legacy"}
// We match on the SIMPLE name (stable across frontends) and pull quoted strings
// out of the argument text for the path.
// ---------------------------------------------------------------------------

val SPRING_MAPPING = Set("RequestMapping","GetMapping","PostMapping","PutMapping","DeleteMapping","PatchMapping")
val JAXRS_VERBS    = Set("GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH")
val SPRING_PARAM_ANN = Set("RequestParam","PathVariable","RequestBody","RequestHeader","CookieValue",
                           "RequestPart","MatrixVariable","ModelAttribute","SessionAttribute","RequestAttribute")
val JAXRS_PARAM_ANN  = Set("QueryParam","PathParam","FormParam","HeaderParam","CookieParam","MatrixParam","BeanParam")
val SERVLET_HANDLERS = Set("doGet","doPost","doPut","doDelete","doHead","doOptions","doTrace","service")

def mappingVerb(annName: String): String = annName match {
  case "GetMapping"    => "GET"
  case "PostMapping"   => "POST"
  case "PutMapping"    => "PUT"
  case "DeleteMapping" => "DELETE"
  case "PatchMapping"  => "PATCH"
  case _               => "ANY"   // RequestMapping with no/extra method= attr
}

// First quoted string inside an annotation's argument text (the route path).
def annFirstString(a: nodes.Annotation): Option[String] = {
  val text = a.astChildren.code.l.mkString(" ")
  """"([^"]*)"""".r.findFirstMatchIn(text).map(_.group(1))
}

// Path declared by a @RequestMapping/@Path annotation on a method or its class.
def annPathOf(anns: Iterator[nodes.Annotation], names: Set[String]): Option[String] =
  anns.toList.find(a => names.contains(a.name)).flatMap(annFirstString)

// Join a class-level path prefix and a method path into one URL pattern.
def joinPath(prefix: String, sub: String): String = {
  val p = if (prefix == null) "" else prefix.trim
  val s = if (sub == null) "" else sub.trim
  val joined = (p.stripSuffix("/") + "/" + s.stripPrefix("/")).replaceAll("/+", "/")
  if (joined.isEmpty) "/" else joined
}

// Render a method's request-bound parameters (annotation + type) for the slice
// header, e.g.  name:@RequestParam:String, body:@RequestBody:String
def paramSummary(m: Method): String =
  m.parameter.filter(_.index > 0).l.map { p =>
    val ann = p.annotation.name.headOption.map("@" + _).getOrElse("")
    val ty  = Option(p.typeFullName).map(_.split("\\.").last).getOrElse("?")
    val nm  = Option(p.name).getOrElse("?")
    s"$nm:${if (ann.nonEmpty) ann + ":" else ""}$ty"
  }.mkString(", ")

// Convenience: the simple class name of a method's declaring type.
def declClass(m: Method): String = m.typeDecl.fullName.headOption.getOrElse("?")

// Framework / runtime packages: never the APPLICATION's own request handlers,
// even when a fat jar / WAR bundles them as non-external classes. App handlers
// that USE these (extend HttpServlet, are annotated @GetMapping, etc.) live in
// the app's own packages — those subclasses are matched by their OWN fullName,
// so excluding these prefixes as entry points is safe and removes the dominant
// source of bytecode noise. (Complements the build-time WEB-INF/lib excludes.)
val FRAMEWORK_PKG =
  ("(java|javax|jakarta|sun|jdk|com\\.sun|org\\.springframework|org\\.apache|org\\.hibernate|" +
   "org\\.slf4j|ch\\.qos|com\\.fasterxml|com\\.google|org\\.eclipse|org\\.junit|org\\.mockito|" +
   "kotlin|scala|groovy|reactor|io\\.netty|io\\.micrometer|org\\.jboss|org\\.glassfish|org\\.yaml)\\..*")
def isFrameworkType(fqn: String): Boolean = fqn != null && fqn.matches(FRAMEWORK_PKG)
// Annotation interfaces (e.g. a bundled @WebServlet) inherit java.lang.annotation.Annotation.
def isAnnotationType(t: TypeDecl): Boolean = t.inheritsFromTypeFullName.exists(_.endsWith("annotation.Annotation"))

// App-scope filter. Bytecode inputs (esp. fat jars / WARs) drag in dependency
// classes that are NOT isExternal; an optional INCLUDE_REGEX env restricts every
// pass to TypeDecls whose fullName matches (e.g. "com\.mycorp\..*"). Unset = keep
// all non-framework, non-skipped methods (correct for source trees and app jars).
val includeRegex = sys.env.getOrElse("INCLUDE_REGEX", "").trim
def inAppScope(m: Method): Boolean = {
  val c = declClass(m)
  !isFrameworkType(c) && (includeRegex.isEmpty || Try(c.matches(includeRegex)).getOrElse(true))
}
def typeInAppScope(t: TypeDecl): Boolean =
  !isFrameworkType(t.fullName) && !isAnnotationType(t) &&
  (includeRegex.isEmpty || Try(t.fullName.matches(includeRegex)).getOrElse(true))
if (includeRegex.nonEmpty) println(s"[*] INCLUDE_REGEX active: only TypeDecls matching /$includeRegex/")

// ===========================================================================
// ROUTE_SPRING: @*Mapping handler methods (Spring MVC + WebFlux)
// ===========================================================================
println("=" * 70)
println("[*] ROUTE_SPRING: @RequestMapping/@GetMapping/... handlers")
println("=" * 70)

val springHandlers = cpg.method
  .where(_.annotation.name(SPRING_MAPPING.toSeq: _*))
  .filterNot(_.isExternal)
  .filterNot(m => isSkipped(m.filename))
  .filter(inAppScope)
  .l
println(s"[*] Found ${springHandlers.size} Spring mapping handler method(s)")

springHandlers.foreach { m =>
  val cls        = declClass(m)
  val methodAnn  = m.annotation.l.find(a => SPRING_MAPPING.contains(a.name))
  val verb       = methodAnn.map(a => mappingVerb(a.name)).getOrElse("ANY")
  val subPath    = methodAnn.flatMap(annFirstString).getOrElse("")
  // class-level @RequestMapping prefix (Spring composes these)
  val classPath  = annPathOf(m.typeDecl.annotation, Set("RequestMapping")).getOrElse("")
  val url        = joinPath(classPath, subPath)
  val label      = s"$verb $url"
  emit("ROUTE_SPRING", label, s"${cls.split("\\.").last}#${m.name}", m, Seq(
    "Routing"  -> s"spring @${methodAnn.map(_.name).getOrElse("RequestMapping")} ($verb $url)",
    "Class"    -> cls,
    "Params"   -> paramSummary(m)
  ))
}
println()

// ===========================================================================
// ROUTE_JAXRS: @GET/@POST/... on @Path resources (Jakarta/Java EE REST)
// ===========================================================================
println("=" * 70)
println("[*] ROUTE_JAXRS: JAX-RS @GET/@POST/... resource methods")
println("=" * 70)

val jaxrsHandlers = cpg.method
  .where(_.annotation.name(JAXRS_VERBS.toSeq: _*))
  .filterNot(_.isExternal)
  .filterNot(m => isSkipped(m.filename))
  .filter(inAppScope)
  .l
println(s"[*] Found ${jaxrsHandlers.size} JAX-RS resource method(s)")

jaxrsHandlers.foreach { m =>
  val cls       = declClass(m)
  val verb      = m.annotation.name.find(JAXRS_VERBS.contains).getOrElse("ANY")
  val subPath   = annPathOf(m.annotation, Set("Path")).getOrElse("")
  val classPath = annPathOf(m.typeDecl.annotation, Set("Path")).getOrElse("")
  val url       = joinPath(classPath, subPath)
  val label     = s"$verb $url"
  emit("ROUTE_JAXRS", label, s"${cls.split("\\.").last}#${m.name}", m, Seq(
    "Routing" -> s"jax-rs @$verb @Path ($url)",
    "Class"   -> cls,
    "Params"  -> paramSummary(m)
  ))
}
println()

// ===========================================================================
// ROUTE_SERVLET: doGet/doPost/... on javax/jakarta HttpServlet subclasses
//
// The URL pattern lives in @WebServlet(value/urlPatterns=...) or in web.xml
// (<servlet-mapping>, out of the CPG) — we surface the annotation pattern when
// present and otherwise note web.xml.
// ===========================================================================
println("=" * 70)
println("[*] ROUTE_SERVLET: HttpServlet doGet/doPost/... handlers")
println("=" * 70)

val servletTypes = cpg.typeDecl
  .filter(_.inheritsFromTypeFullName.exists(s => s.endsWith("servlet.http.HttpServlet") || s.endsWith("servlet.GenericServlet")))
  .filterNot(t => isSkipped(t.filename))
  .filter(typeInAppScope)
  .l
println(s"[*] Found ${servletTypes.size} HttpServlet subclass(es)")

servletTypes.foreach { t =>
  val cls       = t.fullName
  val pattern   = annPathOf(t.annotation, Set("WebServlet")).getOrElse("web.xml <servlet-mapping>")
  val handlers  = t.method.nameExact(SERVLET_HANDLERS.toSeq: _*).filterNot(_.isExternal).l
  if (handlers.isEmpty)
    emitUnresolved("ROUTE_SERVLET", s"$cls ($pattern)", "no doGet/doPost/... method found on servlet subclass")
  else handlers.foreach { m =>
    emit("ROUTE_SERVLET", s"${m.name} $pattern", s"${cls.split("\\.").last}#${m.name}", m, Seq(
      "Routing" -> s"servlet ${m.name} -> $pattern",
      "Class"   -> cls,
      "Params"  -> paramSummary(m)
    ))
  }
}
println()

// ===========================================================================
// CONTROLLER: public methods of controller-ish classes missed by the route
// passes (handlers without a per-method mapping annotation, @RestController
// class default-mapped methods, *Controller/*Resource/*Endpoint by convention).
// emit() dedupe drops anything already sliced as a ROUTE_*.
// ===========================================================================
println("=" * 70)
println("[*] CONTROLLER: @Controller/@RestController/@Path + *Controller classes")
println("=" * 70)

val controllerTypes = cpg.typeDecl
  .filterNot(t => isSkipped(t.filename))
  .filter(typeInAppScope)
  .filter { t =>
    val byAnn  = t.annotation.name.exists(n => Set("Controller","RestController","Path","RestControllerAdvice","ControllerAdvice").contains(n))
    val byName = t.name.matches(".*(Controller|Resource|Endpoint|Servlet|Action|Api|Rest)$")
    byAnn || byName
  }
  .l
println(s"[*] Found ${controllerTypes.size} controller-ish class(es)")

val ctrlMethods = controllerTypes.method
  .isPublic
  .nameNot("<init>", "<clinit>", "<lambda>.*", "<operator>.*", ".*\\$.*")
  .filterNot(_.isExternal)
  .filter(inAppScope)
  .l
println(s"[*] ${ctrlMethods.size} public method(s) on controller-ish classes (pre-dedupe)")

ctrlMethods.foreach { m =>
  val cls = declClass(m)
  emit("CONTROLLER", s"${cls.split("\\.").last}#${m.name}", s"${cls.split("\\.").last}#${m.name}", m, Seq(
    "Class"  -> cls,
    "Params" -> paramSummary(m),
    "Routing" -> "convention/annotated controller method (no per-method mapping resolved)"
  ))
}
println()

// ===========================================================================
// INPUT_SOURCE: framework-agnostic safety net — any method that binds request
// input via a parameter annotation, or reads a (Http)ServletRequest directly.
// Catches custom dispatchers, base-class handlers, @ModelAttribute binders, and
// helpers the framework heuristics above miss. emit() dedupe skips prior slices.
// ===========================================================================
println("=" * 70)
println("[*] INPUT_SOURCE: @RequestParam/@QueryParam/... + ServletRequest readers")
println("=" * 70)

val REQUEST_READ_CALLS =
  "getParameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|" +
  "getHeaderNames|getQueryString|getInputStream|getReader|getCookies|getPart|getParts|" +
  "getPathInfo|getRequestURI|getRequestURL|getRemoteUser|getQueryParameters|getRequestBody"

def bindsRequestInputJava(m: Method): Boolean = {
  val allParamAnn = SPRING_PARAM_ANN ++ JAXRS_PARAM_ANN
  lazy val byParamAnn = m.parameter.annotation.name.exists(allParamAnn.contains)
  // a parameter typed (Http)ServletRequest / jax-rs UriInfo / ContainerRequestContext
  lazy val byReqParam = m.parameter.typeFullName(".*\\.(Http)?ServletRequest|.*\\.UriInfo|.*\\.ContainerRequestContext").nonEmpty
  // a call to a request-reading accessor anywhere in the body
  lazy val byReqCall  = m.ast.isCall.name(REQUEST_READ_CALLS).nonEmpty
  byParamAnn || byReqParam || byReqCall
}

val inputMethods = cpg.method
  .nameNot("<init>", "<clinit>", "<lambda>.*", "<operator>.*", ".*\\$.*")
  .filterNot(_.isExternal)
  .filterNot(m => isSkipped(m.filename))
  .filter(inAppScope)
  .filter(bindsRequestInputJava)
  .l
println(s"[*] Found ${inputMethods.size} method(s) binding/reading request input directly")

inputMethods.foreach { m =>
  val cls    = declClass(m)
  val simple = if (cls == "?") "" else cls.split("\\.").last
  val label  = if (simple.nonEmpty) s"$simple#${m.name}" else m.name
  emit("INPUT_SOURCE", label, label, m, Seq(
    "Class"  -> cls,
    "Params" -> paramSummary(m),
    "Reads"  -> "@RequestParam/@QueryParam/... or ServletRequest accessor"
  ))
}
println()
