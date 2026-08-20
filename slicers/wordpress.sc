// wordpress.sc  — WordPress-specific entry-surface passes.
//
// Concatenated after _prelude.sc (which provides cpg, emit, emitUnresolved,
// collectCallees, sourceWindow, parseBlockCallback, isSkipped, getMethodSource, ...).
//
// Finds visitor-accessible (unauthenticated remote) attack surface in WordPress
// plugins via six WordPress-specific passes, run highest-signal first so
// emit()'s dedupe keeps the most informative type:
//   TYPE 1 REST           — register_rest_route()
//   TYPE 2 SHORTCODE      — add_shortcode()
//   TYPE 3 TEMPLATE_HOOK  — add_action(template_redirect|wp|parse_request|...)
//   TYPE 4 INIT_HOOK      — add_action('init', ...)
//   TYPE 5 BLOCK          — register_block_type() render_callback
//   TYPE 6 AJAX_NOPRIV    — add_action('wp_ajax_nopriv_*', ...)

// ---------------------------------------------------------------------------
// WordPress-specific helpers
// ---------------------------------------------------------------------------

def extractArrayValues(window: String, key: String): List[String] = {
  val pat = s"""['"]${key}['"]\\s*=>\\s*['"]([^'"]+)['"]""".r
  pat.findAllMatchIn(window).map(_.group(1)).toList
}

def restPermissionLevel(window: String): String = {
  if (!window.contains("permission_callback")) return "missing"
  val publicPat =
    """permission_callback['":\s]*=>\s*(['"]__return_true['"]|function\s*\([^)]*\)\s*\{[^}]*return\s+true\s*;[^}]*\})""".r
  val authPat =
    """(is_user_logged_in|current_user_can|__return_false)""".r
  if (publicPat.findFirstIn(window).isDefined)    "public"
  else if (authPat.findFirstIn(window).isDefined) "auth-required"
  else                                            "unknown"
}

def resolveByNameWp(name: String): List[(String, Method)] = {
  if (name.contains("::")) {
    val parts = name.split("::", 2)
    val (cls, meth) = (parts(0), parts(1))
    val r = cpg.method.nameExact(meth).where(_.typeDecl.nameExact(cls)).l
    if (r.nonEmpty) r.map(m => (name, m))
    else cpg.method.nameExact(meth).l.map(m => (s"$name (fuzzy)", m))
  } else {
    cpg.method.nameExact(name).l.map(m => (name, m))
  }
}

def resolveCallbackArg(call: Call, argIdx: Int = 2): List[(String, Method)] = {
  val argOpt = Try(call.argument(argIdx)).toOption
  argOpt match {
    case None => Nil
    case Some(arg) =>
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
          val name = arg.code.stripPrefix("\"").stripSuffix("\"")
                             .stripPrefix("'").stripSuffix("'")
          cpg.method.nameExact(name).l.map(m => (name, m))
        case _ => Nil
      }
  }
}

// ===========================================================================
// TYPE 1: REST API routes — register_rest_route(namespace, route, args)
//
// The callback sits inside the $args array, not as a direct argument, so we
// extract it from source text. We also classify the permission_callback to
// surface publicly accessible routes.
// ===========================================================================
println("=" * 70)
println("[*] TYPE 1: REST API routes (register_rest_route)")
println("=" * 70)

val restCalls = cpg.call.nameExact("register_rest_route")
  .filterNot(c => isSkipped(c.method.filename)).l
println(s"[*] Found ${restCalls.size} register_rest_route call(s)")

restCalls.foreach { call =>
  val ns    = Try(call.argument(1).code.stripPrefix("\"").stripSuffix("\"")
                                       .stripPrefix("'").stripSuffix("'")).getOrElse("?")
  val route = Try(call.argument(2).code.stripPrefix("\"").stripSuffix("\"")
                                       .stripPrefix("'").stripSuffix("'")).getOrElse("?")
  val label = s"$ns$route"
  val win   = sourceWindow(call, 35)
  val perm  = restPermissionLevel(win)

  val cbNames = extractArrayValues(win, "callback")

  if (cbNames.isEmpty) {
    val fallback = Try(resolveCallbackArg(call, 3)).getOrElse(Nil)
    if (fallback.isEmpty)
      emitUnresolved("REST", label, s"[perm=$perm] could not resolve callback")
    else
      fallback.foreach { case (desc, m) => emit("REST", label, desc, m, Seq("Permission" -> perm)) }
  } else {
    cbNames.foreach { name =>
      val resolved = resolveByNameWp(name)
      if (resolved.isEmpty)
        emitUnresolved("REST", s"$label[$name]", s"[perm=$perm] no CPG method for '$name'")
      else
        resolved.foreach { case (desc, m) => emit("REST", label, desc, m, Seq("Permission" -> perm)) }
    }
  }
}
println()

// ===========================================================================
// TYPE 2: Shortcodes — add_shortcode(tag, callback)
//
// Shortcodes are rendered by any user viewing content that includes them
// (including unauthenticated visitors). The callback receives user-supplied
// $atts and optional $content, making them a common injection target.
// ===========================================================================
println("=" * 70)
println("[*] TYPE 2: Shortcodes (add_shortcode)")
println("=" * 70)

val shortcodeCalls = cpg.call.nameExact("add_shortcode")
  .filterNot(c => isSkipped(c.method.filename)).l
println(s"[*] Found ${shortcodeCalls.size} add_shortcode call(s)")

shortcodeCalls.foreach { call =>
  val tag = Try(call.argument(1).code.stripPrefix("\"").stripSuffix("\"")
                                     .stripPrefix("'").stripSuffix("'")).getOrElse("?")
  resolveCallbackArg(call, 2) match {
    case Nil     => emitUnresolved("SHORTCODE", tag, call.argument(2).code)
    case entries => entries.foreach { case (desc, m) => emit("SHORTCODE", tag, desc, m) }
  }
}
println()

// ===========================================================================
// TYPE 3: Template / early-request hooks — add_action(hook, callback)
//
// These hooks fire on every WordPress page load before authentication is
// checked, making any registered callback reachable by unauthenticated users.
// ===========================================================================
println("=" * 70)
println("[*] TYPE 3: Template & request hooks")
println("=" * 70)

val templateHookPat = """["'](template_redirect|parse_request|send_headers|wp_loaded|plugins_loaded|wp)["']"""

val templateActionCalls = cpg.call
  .nameExact("add_action")
  .where(_.argument(1).isLiteral.code(templateHookPat))
  .filterNot(c => isSkipped(c.method.filename))
  .l

println(s"[*] Found ${templateActionCalls.size} template/request hook registration(s)")

templateActionCalls.foreach { call =>
  val hook = call.argument(1).code.stripPrefix("\"").stripSuffix("\"")
                                  .stripPrefix("'").stripSuffix("'")
  resolveCallbackArg(call, 2) match {
    case Nil     => emitUnresolved("TEMPLATE_HOOK", hook, call.argument(2).code)
    case entries => entries.foreach { case (desc, m) => emit("TEMPLATE_HOOK", hook, desc, m) }
  }
}
println()

// ===========================================================================
// TYPE 4: Init hooks — add_action('init', callback)
//
// The 'init' hook fires on every request (admin and frontend) after WordPress
// is loaded but before headers are sent. Many plugins use it to route custom
// requests by inspecting $_GET/$_POST.
// ===========================================================================
println("=" * 70)
println("[*] TYPE 4: Init hooks (add_action('init', ...))")
println("=" * 70)

val initCalls = cpg.call
  .nameExact("add_action")
  .where(_.argument(1).isLiteral.code("""["']init["']"""))
  .filterNot(c => isSkipped(c.method.filename))
  .l

println(s"[*] Found ${initCalls.size} init hook registration(s)")

initCalls.foreach { call =>
  resolveCallbackArg(call, 2) match {
    case Nil     => emitUnresolved("INIT_HOOK", "init", call.argument(2).code)
    case entries => entries.foreach { case (desc, m) => emit("INIT_HOOK", "init", desc, m) }
  }
}
println()

// ===========================================================================
// TYPE 5: Block render callbacks — register_block_type(name, args)
//
// Blocks with a server-side render_callback execute PHP on every page that
// includes the block, regardless of visitor authentication.
// ===========================================================================
println("=" * 70)
println("[*] TYPE 5: Block render callbacks (register_block_type)")
println("=" * 70)

val blockCalls = cpg.call
  .nameExact("register_block_type", "register_block_type_from_metadata")
  .filterNot(c => isSkipped(c.method.filename))
  .l

println(s"[*] Found ${blockCalls.size} register_block_type call(s)")

blockCalls.foreach { call =>
  val blockName = Try(call.argument(1).code.stripPrefix("\"").stripSuffix("\"")
                                           .stripPrefix("'").stripSuffix("'")).getOrElse("?")
  val win = sourceWindow(call, 35)
  val cbNames = extractArrayValues(win, "render_callback")

  if (cbNames.isEmpty) {
    println(s"[~] [BLOCK] $blockName — no render_callback (client-side only, skipping)")
  } else {
    cbNames.foreach { name =>
      val resolved = resolveByNameWp(name)
      if (resolved.isEmpty)
        emitUnresolved("BLOCK", blockName, s"render_callback='$name' not found in CPG")
      else
        resolved.foreach { case (desc, m) =>
          emit("BLOCK", blockName, desc, m, Seq("render_callback" -> name))
        }
    }
  }
}
println()

// ===========================================================================
// TYPE 6: wp_ajax_nopriv handlers — add_action('wp_ajax_nopriv_*', callback)
//
// These AJAX handlers are callable by unauthenticated visitors via
// admin-ajax.php?action=<name>. A very common unauthenticated entry point.
// ===========================================================================
println("=" * 70)
println("[*] TYPE 6: AJAX nopriv handlers (wp_ajax_nopriv_*)")
println("=" * 70)

val noprivCalls = cpg.call
  .nameExact("add_action")
  .where(_.argument(1).isLiteral.code(".*wp_ajax_nopriv.*"))
  .filterNot(c => isSkipped(c.method.filename))
  .l

println(s"[*] Found ${noprivCalls.size} wp_ajax_nopriv hook(s)")

noprivCalls.foreach { call =>
  val hookCode = call.argument(1).code
    .stripPrefix("\"").stripSuffix("\"")
    .stripPrefix("'").stripSuffix("'")
  val actionName = hookCode.replaceFirst("^wp_ajax_nopriv_", "")

  resolveCallbackArg(call, 2) match {
    case Nil     => emitUnresolved("AJAX_NOPRIV", actionName, call.argument(2).code)
    case entries => entries.foreach { case (desc, m) =>
      emit("AJAX_NOPRIV", actionName, desc, m, Seq("Hook" -> hookCode))
    }
  }
}
println()
