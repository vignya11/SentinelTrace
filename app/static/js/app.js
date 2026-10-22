(function () {
  "use strict";
  var csrf = (document.querySelector('meta[name="csrf"]') || {}).content || "";
  document.querySelectorAll("[data-nav-toggle]").forEach(function (b) {
    b.addEventListener("click", function () { document.body.classList.toggle("nav-open"); });
  });
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!window.confirm(f.dataset.confirm)) e.preventDefault(); });
  });

  var NS = "http://www.w3.org/2000/svg";
  function el(n, a, t) { var e = document.createElementNS(NS, n); for (var k in a) e.setAttribute(k, a[k]); if (t !== undefined) e.textContent = t; return e; }

  function drawTrend(box, data) {
    box.classList.remove("skeleton"); box.textContent = "";
    var W = 720, H = 210, L = 34, B = 24, T = 8, max = Math.max.apply(null, data.map(function (d) { return d.success + d.failure; }).concat([1]));
    var svg = el("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Logins per hour, last 24 hours" });
    [0, .5, 1].forEach(function (f) {
      var y = T + (H - B - T) * (1 - f);
      svg.appendChild(el("line", { x1: L, x2: W, y1: y, y2: y, stroke: "#d8dfeb" }));
      svg.appendChild(el("text", { x: L - 6, y: y + 4, "text-anchor": "end", "font-size": 11, fill: "#56667f" }, Math.round(max * f)));
    });
    var bw = (W - L) / data.length;
    data.forEach(function (d, i) {
      var x = L + i * bw + 3, w = bw - 6, hs = (H - B - T) * d.success / max, hf = (H - B - T) * d.failure / max;
      var t1 = el("rect", { x: x, y: H - B - hs, width: w, height: hs, fill: "#2a66f0", rx: 2 }); t1.appendChild(el("title", {}, d.hour + ":00 UTC - " + d.success + " successful"));
      var t2 = el("rect", { x: x, y: H - B - hs - hf, width: w, height: hf, fill: "#c0262d", rx: 2 }); t2.appendChild(el("title", {}, d.hour + ":00 UTC - " + d.failure + " failed"));
      svg.appendChild(t1); svg.appendChild(t2);
      if (i % 4 === 0) svg.appendChild(el("text", { x: x + w / 2, y: H - 6, "text-anchor": "middle", "font-size": 11, fill: "#56667f" }, d.hour.slice(11) + "h"));
    });
    box.appendChild(svg);
  }

  function setMetrics(m) {
    document.querySelectorAll("[data-m]").forEach(function (n) {
      var v = m[n.dataset.m]; n.textContent = (v === null || v === undefined) ? "n/a" : v + (n.dataset.suffix || "");
    });
    var box = document.getElementById("trend"); if (box) drawTrend(box, m.hourly);
  }

  var trendData = document.getElementById("trend-data");
  if (trendData) drawTrend(document.getElementById("trend"), JSON.parse(trendData.textContent));

  var body = document.getElementById("live-body");
  if (body) {
    var status = document.getElementById("live-status"), lastId = parseInt(body.dataset.lastId || "0", 10), timer = null, poll = null;
    function addRow(d) {
      if (d.id <= lastId) return; lastId = d.id;
      var tr = document.createElement("tr"); tr.className = "new";
      [d.ts.slice(0, 19).replace("T", " "), d.event_type.replace(/_/g, " "), d.outcome, d.username || "-", d.source_ip + (d.synthetic ? " (synthetic)" : "")]
        .forEach(function (v) { var td = document.createElement("td"); td.textContent = v; tr.appendChild(td); });
      var empty = document.getElementById("live-empty"); if (empty) empty.remove();
      body.insertBefore(tr, body.firstChild); while (body.children.length > 12) body.removeChild(body.lastChild);
      clearTimeout(timer); timer = setTimeout(refresh, 1200);
    }
    function refresh() { fetch("/api/v1/dashboard/metrics", { credentials: "same-origin" }).then(function (r) { return r.ok ? r.json() : null; }).then(function (m) { if (m) setMetrics(m); }); }
    function setLive(on, txt) { status.className = "live" + (on ? " on" : ""); status.lastChild.textContent = " " + txt; }
    function startPolling() {
      if (poll) return; setLive(false, "Polling every 5 s (stream unavailable)");
      poll = setInterval(function () {
        fetch("/api/v1/events?after_id=" + lastId + "&per_page=50", { credentials: "same-origin" }).then(function (r) { return r.ok ? r.json() : null; })
          .then(function (j) { if (j) j.events.forEach(addRow); });
      }, 5000);
    }
    if (window.EventSource) {
      var es = new EventSource("/stream/events?last_id=" + lastId);  // browser auto-reconnects and sends Last-Event-ID
      es.onopen = function () { setLive(true, "Live"); };
      es.addEventListener("auth_event", function (e) { addRow(JSON.parse(e.data)); });
      es.onerror = function () { if (es.readyState === 2) { startPolling(); } else { setLive(false, "Reconnecting..."); } };
    } else { startPolling(); }
  }
})();
