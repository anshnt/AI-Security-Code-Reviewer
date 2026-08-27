/**
 * Browser-side chart rendering, shipped as a string.
 *
 * The dashboard has no build step and no external requests - a security tool
 * that pulls a charting library off a CDN at page load is making the argument
 * against itself. So the charts are drawn as SVG by this script, which reads
 * its data from an inline JSON block.
 *
 * Kept as a template literal rather than a separate asset so the server has
 * exactly one file to serve and nothing to resolve on disk.
 */
export const CLIENT_SCRIPT = String.raw`
(function () {
  'use strict';

  var payload = JSON.parse(document.getElementById('dashboard-data').textContent);
  var trend = payload.trend;
  var severity = payload.severity;
  var categories = payload.categories;
  var SEVERITY_ORDER = payload.severityOrder;

  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  var tooltip = document.getElementById('tooltip');

  function showTooltip(html, x, y) {
    tooltip.innerHTML = html;
    tooltip.hidden = false;
    var box = tooltip.getBoundingClientRect();
    var left = x + 14;
    if (left + box.width > window.innerWidth - 8) left = x - box.width - 14;
    tooltip.style.left = left + 'px';
    tooltip.style.top = Math.max(8, y - box.height - 12) + 'px';
  }

  function hideTooltip() {
    tooltip.hidden = true;
  }

  function svgEl(name, attrs) {
    var node = document.createElementNS('http://www.w3.org/2000/svg', name);
    for (var key in attrs) {
      if (attrs[key] !== null && attrs[key] !== undefined) node.setAttribute(key, String(attrs[key]));
    }
    return node;
  }

  function niceMax(value) {
    if (value <= 5) return 5;
    var magnitude = Math.pow(10, Math.floor(Math.log10(value)));
    var scaled = value / magnitude;
    var step = scaled <= 1 ? 1 : scaled <= 2 ? 2 : scaled <= 5 ? 5 : 10;
    return step * magnitude;
  }

  function formatDate(iso) {
    var parts = iso.split('-');
    var d = new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2]));
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  /* ---------------------------------------------------------------- *
   * Open findings over time - one series, so no legend: the title
   * names it. Crosshair plus tooltip, per the interaction baseline.
   * ---------------------------------------------------------------- */
  function drawOpenTrend() {
    var host = document.getElementById('chart-open');
    if (!host || trend.length === 0) return;
    host.textContent = '';

    var width = host.clientWidth || 720;
    var height = 260;
    var pad = { top: 16, right: 20, bottom: 30, left: 44 };
    var plotW = Math.max(10, width - pad.left - pad.right);
    var plotH = height - pad.top - pad.bottom;

    var max = niceMax(Math.max.apply(null, trend.map(function (p) { return p.open; })).valueOf() || 1);
    var svg = svgEl('svg', { viewBox: '0 0 ' + width + ' ' + height, width: '100%', height: height, role: 'img' });
    svg.setAttribute('aria-label', 'Open findings per day over the selected window');

    var x = function (i) { return pad.left + (trend.length === 1 ? plotW / 2 : (i / (trend.length - 1)) * plotW); };
    var y = function (v) { return pad.top + plotH - (v / max) * plotH; };

    // Recessive solid hairline grid, never dashed.
    for (var t = 0; t <= 4; t += 1) {
      var value = (max / 4) * t;
      var gy = y(value);
      svg.appendChild(svgEl('line', {
        x1: pad.left, x2: pad.left + plotW, y1: gy, y2: gy,
        stroke: css('--grid'), 'stroke-width': 1, 'shape-rendering': 'crispEdges'
      }));
      var label = svgEl('text', { x: pad.left - 8, y: gy + 4, 'text-anchor': 'end', class: 'axis-label' });
      label.textContent = String(Math.round(value));
      svg.appendChild(label);
    }

    var areaPoints = trend.map(function (p, i) { return x(i) + ',' + y(p.open); });
    var area = svgEl('path', {
      d: 'M' + pad.left + ',' + y(0) + ' L' + areaPoints.join(' L') + ' L' + x(trend.length - 1) + ',' + y(0) + ' Z',
      fill: 'url(#openFill)', stroke: 'none'
    });
    var defs = svgEl('defs', {});
    var gradient = svgEl('linearGradient', { id: 'openFill', x1: 0, y1: 0, x2: 0, y2: 1 });
    gradient.appendChild(svgEl('stop', { offset: '0%', 'stop-color': css('--series-1'), 'stop-opacity': 0.22 }));
    gradient.appendChild(svgEl('stop', { offset: '100%', 'stop-color': css('--series-1'), 'stop-opacity': 0.02 }));
    defs.appendChild(gradient);
    svg.appendChild(defs);
    svg.appendChild(area);

    svg.appendChild(svgEl('polyline', {
      points: areaPoints.join(' '),
      fill: 'none', stroke: css('--series-1'), 'stroke-width': 2,
      'stroke-linejoin': 'round', 'stroke-linecap': 'round'
    }));

    // Selective direct label: the final value only, never one per point.
    var last = trend[trend.length - 1];
    var endLabel = svgEl('text', {
      x: x(trend.length - 1), y: y(last.open) - 18, 'text-anchor': 'end', class: 'end-label'
    });
    endLabel.textContent = last.open + ' open';
    svg.appendChild(endLabel);

    var axisEvery = Math.max(1, Math.ceil(trend.length / 7));
    trend.forEach(function (point, i) {
      if (i % axisEvery !== 0 && i !== trend.length - 1) return;
      var tick = svgEl('text', { x: x(i), y: height - 10, 'text-anchor': 'middle', class: 'axis-label' });
      tick.textContent = formatDate(point.date);
      svg.appendChild(tick);
    });

    var crosshair = svgEl('line', {
      x1: 0, x2: 0, y1: pad.top, y2: pad.top + plotH,
      stroke: css('--text-muted'), 'stroke-width': 1, opacity: 0
    });
    svg.appendChild(crosshair);
    var marker = svgEl('circle', {
      r: 5, fill: css('--series-1'), stroke: css('--surface-raised'), 'stroke-width': 2, opacity: 0
    });
    svg.appendChild(marker);

    var hit = svgEl('rect', { x: pad.left, y: pad.top, width: plotW, height: plotH, fill: 'transparent' });
    svg.appendChild(hit);

    hit.addEventListener('mousemove', function (event) {
      var rect = svg.getBoundingClientRect();
      var relative = ((event.clientX - rect.left) / rect.width) * width;
      var index = Math.round(((relative - pad.left) / plotW) * (trend.length - 1));
      index = Math.max(0, Math.min(trend.length - 1, index));
      var point = trend[index];
      crosshair.setAttribute('x1', x(index));
      crosshair.setAttribute('x2', x(index));
      crosshair.setAttribute('opacity', 0.4);
      marker.setAttribute('cx', x(index));
      marker.setAttribute('cy', y(point.open));
      marker.setAttribute('opacity', 1);
      showTooltip(
        '<strong>' + point.date + '</strong>' +
        '<span>' + point.open + ' open</span>' +
        '<span>+' + point.introduced + ' introduced</span>' +
        '<span>-' + point.resolved + ' resolved</span>',
        event.clientX, event.clientY
      );
    });
    hit.addEventListener('mouseleave', function () {
      crosshair.setAttribute('opacity', 0);
      marker.setAttribute('opacity', 0);
      hideTooltip();
    });

    host.appendChild(svg);
  }

  /* ---------------------------------------------------------------- *
   * Introduced vs resolved. Polarity is geometric - up is new work
   * arriving, down is work cleared - so the two series never depend on
   * a red/green distinction that colour-blind readers cannot make.
   * ---------------------------------------------------------------- */
  function drawFlow() {
    var host = document.getElementById('chart-flow');
    if (!host || trend.length === 0) return;
    host.textContent = '';

    var width = host.clientWidth || 720;
    var height = 240;
    var pad = { top: 18, right: 20, bottom: 30, left: 44 };
    var plotW = Math.max(10, width - pad.left - pad.right);
    var plotH = height - pad.top - pad.bottom;
    var mid = pad.top + plotH / 2;

    var peak = Math.max(1, Math.max.apply(null, trend.map(function (p) {
      return Math.max(p.introduced, p.resolved);
    })));
    var max = niceMax(peak);

    var svg = svgEl('svg', { viewBox: '0 0 ' + width + ' ' + height, width: '100%', height: height, role: 'img' });
    svg.setAttribute('aria-label', 'Findings introduced and resolved per day');

    // 2px surface gap between adjacent bars rather than a stroke around them.
    var slot = plotW / trend.length;
    var barW = Math.max(2, slot - 2);
    var scale = (plotH / 2) / max;
    var radius = Math.min(4, barW / 2);

    [0.5, 1].forEach(function (fraction) {
      [-1, 1].forEach(function (sign) {
        var gy = mid - sign * fraction * (plotH / 2);
        svg.appendChild(svgEl('line', {
          x1: pad.left, x2: pad.left + plotW, y1: gy, y2: gy,
          stroke: css('--grid'), 'stroke-width': 1, 'shape-rendering': 'crispEdges'
        }));
      });
    });

    trend.forEach(function (point, i) {
      var left = pad.left + i * slot + 1;
      if (point.introduced > 0) {
        var h = Math.max(2, point.introduced * scale);
        svg.appendChild(svgEl('rect', {
          x: left, y: mid - h, width: barW, height: h,
          rx: radius, fill: css('--series-1'), class: 'bar'
        }));
      }
      if (point.resolved > 0) {
        var rh = Math.max(2, point.resolved * scale);
        svg.appendChild(svgEl('rect', {
          x: left, y: mid, width: barW, height: rh,
          rx: radius, fill: css('--series-2'), class: 'bar'
        }));
      }
      var hover = svgEl('rect', {
        x: left, y: pad.top, width: barW, height: plotH, fill: 'transparent', class: 'hit'
      });
      hover.addEventListener('mouseenter', function (event) {
        showTooltip(
          '<strong>' + point.date + '</strong>' +
          '<span>+' + point.introduced + ' introduced</span>' +
          '<span>-' + point.resolved + ' resolved</span>',
          event.clientX, event.clientY
        );
      });
      hover.addEventListener('mouseleave', hideTooltip);
      svg.appendChild(hover);
    });

    svg.appendChild(svgEl('line', {
      x1: pad.left, x2: pad.left + plotW, y1: mid, y2: mid,
      stroke: css('--border'), 'stroke-width': 1, 'shape-rendering': 'crispEdges'
    }));

    var upper = svgEl('text', { x: pad.left - 8, y: mid - plotH / 2 + 4, 'text-anchor': 'end', class: 'axis-label' });
    upper.textContent = String(max);
    svg.appendChild(upper);
    var lower = svgEl('text', { x: pad.left - 8, y: mid + plotH / 2 + 4, 'text-anchor': 'end', class: 'axis-label' });
    lower.textContent = String(max);
    svg.appendChild(lower);
    // The baseline is the zero of both arms; labelling it removes the ambiguity
    // of two identical numbers at top and bottom.
    var zero = svgEl('text', { x: pad.left - 8, y: mid + 4, 'text-anchor': 'end', class: 'axis-label' });
    zero.textContent = '0';
    svg.appendChild(zero);

    var axisEvery = Math.max(1, Math.ceil(trend.length / 7));
    trend.forEach(function (point, i) {
      if (i % axisEvery !== 0 && i !== trend.length - 1) return;
      var tick = svgEl('text', {
        x: pad.left + i * slot + barW / 2, y: height - 10, 'text-anchor': 'middle', class: 'axis-label'
      });
      tick.textContent = formatDate(point.date);
      svg.appendChild(tick);
    });

    host.appendChild(svg);
  }

  /* ---------------------------------------------------------------- *
   * Horizontal bars for severity (ordinal ramp) and category (one
   * colour, because the categories have no order). Both direct-label
   * every bar, which is also what relieves the contrast warning on the
   * lighter ramp steps.
   * ---------------------------------------------------------------- */
  function drawBars(hostId, rows, colorFor) {
    var host = document.getElementById(hostId);
    if (!host) return;
    host.textContent = '';
    var total = rows.reduce(function (sum, row) { return sum + row.value; }, 0);
    if (total === 0) {
      var empty = document.createElement('p');
      empty.className = 'empty';
      empty.textContent = 'Nothing open in this window.';
      host.appendChild(empty);
      return;
    }
    var max = Math.max.apply(null, rows.map(function (row) { return row.value; }));
    var list = document.createElement('div');
    list.className = 'bar-rows';

    rows.forEach(function (row) {
      var item = document.createElement('div');
      item.className = 'bar-row';

      var label = document.createElement('span');
      label.className = 'bar-label';
      label.textContent = row.label;

      var track = document.createElement('div');
      track.className = 'bar-track';
      var fill = document.createElement('div');
      fill.className = 'bar-fill';
      fill.style.width = (max === 0 ? 0 : (row.value / max) * 100) + '%';
      fill.style.background = colorFor(row);
      // A zero must render as nothing. The stylesheet gives every fill a 2px
      // floor so a small non-zero value stays visible; applied to a zero it
      // would draw a mark for data that does not exist.
      if (row.value === 0) fill.style.minWidth = '0';
      track.appendChild(fill);

      var value = document.createElement('span');
      value.className = 'bar-value';
      value.textContent = String(row.value);

      item.appendChild(label);
      item.appendChild(track);
      item.appendChild(value);

      item.addEventListener('mouseenter', function (event) {
        var share = total === 0 ? 0 : Math.round((row.value / total) * 100);
        showTooltip(
          '<strong>' + row.label + '</strong><span>' + row.value + ' open (' + share + '% of open findings)</span>',
          event.clientX, event.clientY
        );
      });
      item.addEventListener('mouseleave', hideTooltip);
      list.appendChild(item);
    });

    host.appendChild(list);
  }

  function drawAll() {
    drawOpenTrend();
    drawFlow();
    drawBars('chart-severity', severity, function (row) { return row.color; });
    drawBars('chart-category', categories, function () { return css('--series-1'); });
  }

  drawAll();

  var resizeTimer = null;
  window.addEventListener('resize', function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(drawAll, 120);
  });

  // Theme toggle. Persisted per viewer; a failure to read storage must not
  // stop the page rendering, so every access is guarded.
  var toggle = document.getElementById('theme-toggle');
  function currentTheme() {
    var explicit = document.documentElement.getAttribute('data-theme');
    if (explicit) return explicit;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  try {
    var stored = localStorage.getItem('dashboard-theme');
    if (stored === 'dark' || stored === 'light') document.documentElement.setAttribute('data-theme', stored);
  } catch (error) { /* storage unavailable; fall back to the OS setting */ }
  if (toggle) {
    toggle.addEventListener('click', function () {
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('dashboard-theme', next); } catch (error) { /* ignore */ }
      drawAll();
    });
  }
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', drawAll);

  // The table view is the accessibility fallback for every chart above.
  var tableToggle = document.getElementById('table-toggle');
  if (tableToggle) {
    tableToggle.addEventListener('click', function () {
      var panel = document.getElementById('trend-table');
      var hidden = panel.hasAttribute('hidden');
      if (hidden) panel.removeAttribute('hidden');
      else panel.setAttribute('hidden', '');
      tableToggle.textContent = hidden ? 'Hide data table' : 'Show data table';
      tableToggle.setAttribute('aria-expanded', hidden ? 'true' : 'false');
    });
  }

  // Filters submit on change so the row behaves like one control.
  var form = document.getElementById('filters');
  if (form) {
    Array.prototype.forEach.call(form.querySelectorAll('select'), function (select) {
      select.addEventListener('change', function () { form.submit(); });
    });
  }
})();
`;
