// Runs before first paint: re-applies the visitor's own light/dark choice over the admin-chosen default theme.
(function () {
  var d = document.documentElement, m;
  try { m = localStorage.getItem("it-mode"); } catch (e) { m = null; }
  if ((m === "light" || m === "dark") && m !== d.getAttribute("data-mode")) { d.setAttribute("data-theme", m); d.setAttribute("data-mode", m); }
})();
