export function createResponsiveShell({node, icon, tr}) {
  const workspace = document.getElementById("workspace"), sidebar = workspace.querySelector(".sidebar");
  const main = workspace.querySelector("main"), header = main.querySelector(".topbar");
  const mobile = matchMedia("(max-width: 767px)");
  const toggle = node("button", "quiet mobile-nav-toggle");
  toggle.type = "button"; toggle.id = "navigation-toggle";
  toggle.title = tr("Main navigation"); toggle.setAttribute("aria-label", tr("Main navigation"));
  sidebar.id = "panel-sidebar"; toggle.setAttribute("aria-controls", sidebar.id);
  toggle.setAttribute("aria-expanded", "false"); toggle.append(icon("menu"));
  header.prepend(toggle);
  const close = node("button", "quiet mobile-nav-close");
  close.type = "button"; close.title = tr("Close navigation"); close.setAttribute("aria-label", tr("Close navigation"));
  close.append(icon("x")); sidebar.prepend(close);
  const scrim = node("div", "sidebar-scrim"); scrim.hidden = true;
  workspace.append(scrim);
  let opened = false, previousFocus = null, openMenu = null;
  const closeMenus = (except = null) => {
    if (openMenu && openMenu !== except) {openMenu.open = false; openMenu = null;}
    for (const menu of workspace.querySelectorAll('.action-menu[open]')) if (menu !== except) menu.open = false;
  };
  workspace.addEventListener('toggle', event => {
    if (event.target.matches('.action-menu') && event.target.open) {closeMenus(event.target); openMenu = event.target;}
  }, true);
  document.addEventListener('pointerdown', event => {
    for (const menu of workspace.querySelectorAll('.action-menu[open]')) if (!menu.contains(event.target)) menu.open = false;
  });
  document.addEventListener('keydown', event => {
    if (event.key !== 'Escape' || document.querySelector('dialog[open]')) return;
    const menu = workspace.querySelector('.action-menu[open]');
    if (menu) { event.preventDefault(); menu.open = false; menu.querySelector('summary').focus(); }
  });

  function setOpen(value, restore = true) {
    opened = Boolean(value && mobile.matches);
    if (opened) previousFocus = document.activeElement;
    workspace.classList.toggle("navigation-open", opened);
    toggle.setAttribute("aria-expanded", String(opened)); scrim.hidden = !opened;
    main.inert = opened; sidebar.inert = mobile.matches && !opened;
    if (opened) {
      sidebar.setAttribute("role", "dialog"); sidebar.setAttribute("aria-modal", "true");
      sidebar.setAttribute("aria-label", tr("Main navigation")); close.focus();
    } else {
      sidebar.removeAttribute("role"); sidebar.removeAttribute("aria-modal");
      if (restore && previousFocus?.isConnected && !previousFocus.closest("[inert]")) previousFocus.focus();
      else if (mobile.matches && sidebar.contains(document.activeElement)) toggle.focus({preventScroll: true});
      previousFocus = null;
    }
  }
  function resize() {
    if (!mobile.matches || !opened) setOpen(false, false);
    closeMenus();
  }
  toggle.addEventListener("click", () => setOpen(!opened));
  close.addEventListener("click", () => setOpen(false)); scrim.addEventListener("click", () => setOpen(false));
  sidebar.addEventListener("click", event => {
    if (event.target.closest("[data-view], #lock-panel, #mode-switch, .doc-toggle")) setOpen(false, false);
  });
  window.addEventListener("tgwitness:route", event => {
    closeMenus();
    if (event.detail?.reason !== "initial") setOpen(false, false);
  });
  window.addEventListener("tgwitness:lock", () => {closeMenus();setOpen(false, false);});
  document.addEventListener("keydown", event => {
    if (!opened) return;
    if (event.key === "Escape") { event.preventDefault(); setOpen(false); return; }
    if (event.key !== "Tab") return;
    const controls = [...sidebar.querySelectorAll("a[href],button,input,select,summary,[tabindex='0']")]
      .filter(control => !control.disabled && control.checkVisibility());
    const first = controls[0], last = controls.at(-1);
    if (event.shiftKey && (document.activeElement === first || !sidebar.contains(document.activeElement))) {
      event.preventDefault(); last?.focus();
    } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  });
  mobile.addEventListener("change", resize); resize();
  return {close: () => setOpen(false, false)};
}
