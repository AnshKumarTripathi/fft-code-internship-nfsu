(function () {
  function parsePayload(id) {
    var el = document.getElementById(id);
    if (!el) return null;
    try {
      return JSON.parse(el.textContent);
    } catch (err) {
      console.warn("chart payload parse failed", id, err);
      return null;
    }
  }

  function pad2(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function formatUtcTick(value) {
    if (value == null || value === "") return "";
    var text = String(value);
    var parsed = new Date(text);
    if (isNaN(parsed.getTime())) {
      var iso = text.replace(" ", "T");
      parsed = new Date(iso.endsWith("Z") || /[+-]\d\d:\d\d$/.test(iso) ? iso : iso + "Z");
    }
    if (isNaN(parsed.getTime())) return text.slice(5, 16);
    return (
      pad2(parsed.getUTCMonth() + 1) +
      "-" +
      pad2(parsed.getUTCDate()) +
      " " +
      pad2(parsed.getUTCHours()) +
      ":" +
      pad2(parsed.getUTCMinutes())
    );
  }

  function overlayPlugin() {
    return {
      id: "flagOverlays",
      afterDatasetsDraw: function (chart) {
        var overlays = (chart.data && chart.data.overlays) || [];
        var labels = chart.data.labels || [];
        if (!overlays.length || !labels.length) return;
        var xScale = chart.scales.x;
        var area = chart.chartArea;
        if (!xScale || !area) return;
        var ctx = chart.ctx;
        var colors = {
          statistical: "rgba(161, 74, 0, 0.18)",
          spectral: "rgba(11, 110, 79, 0.18)",
        };
        overlays.forEach(function (band) {
          var start = Date.parse(band.start);
          var end = Date.parse(band.end);
          if (isNaN(start) || isNaN(end)) return;
          var leftIndex = 0;
          var rightIndex = labels.length - 1;
          for (var i = 0; i < labels.length; i++) {
            var ts = Date.parse(labels[i]);
            if (isNaN(ts)) continue;
            if (ts <= start) leftIndex = i;
            if (ts <= end) rightIndex = i;
          }
          var x1 = xScale.getPixelForValue(leftIndex);
          var x2 = xScale.getPixelForValue(rightIndex);
          if (x2 < x1) {
            var tmp = x1;
            x1 = x2;
            x2 = tmp;
          }
          var width = Math.max(2, x2 - x1);
          ctx.save();
          ctx.fillStyle = colors[band.source] || "rgba(26, 26, 26, 0.12)";
          ctx.fillRect(x1, area.top, width, area.bottom - area.top);
          ctx.restore();
        });
      },
    };
  }

  function baseOptions() {
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#1a1a1a",
          titleFont: { family: "ui-monospace, monospace", size: 11 },
          bodyFont: { family: "ui-monospace, monospace", size: 11 },
        },
      },
      scales: {
        x: {
          ticks: {
            color: "#5c5a55",
            maxRotation: 0,
            autoSkip: true,
            maxTicksLimit: 8,
            font: { family: "ui-monospace, monospace", size: 10 },
            callback: function (value) {
              var label = this.getLabelForValue(value);
              return formatUtcTick(label);
            },
          },
          grid: { color: "#ebe8e1" },
        },
        y: {
          ticks: {
            color: "#5c5a55",
            font: { family: "ui-monospace, monospace", size: 10 },
          },
          grid: { color: "#ebe8e1" },
          beginAtZero: true,
        },
      },
    };
  }

  function renderActivity(canvasId, payloadId) {
    var canvas = document.getElementById(canvasId);
    var data = parsePayload(payloadId);
    if (!canvas || !data || !window.Chart) return;
    var labels = (data.labels || []).map(function (v) {
      return v || "";
    });
    new Chart(canvas, {
      type: "line",
      plugins: [overlayPlugin()],
      data: {
        labels: labels,
        overlays: data.overlays || [],
        datasets: [
          {
            label: "event_count",
            data: data.values || [],
            borderColor: "#0b6e4f",
            backgroundColor: "rgba(11, 110, 79, 0.12)",
            borderWidth: 1.5,
            pointRadius: 0,
            tension: 0.15,
            fill: true,
          },
        ],
      },
      options: baseOptions(),
    });
  }

  function renderPsd(canvasId, payloadId) {
    var canvas = document.getElementById(canvasId);
    var data = parsePayload(payloadId);
    if (!canvas || !data || !window.Chart) return;
    new Chart(canvas, {
      type: "line",
      data: {
        labels: data.freq || [],
        datasets: [
          {
            label: "psd_norm",
            data: data.psd || [],
            borderColor: "#1a1a1a",
            backgroundColor: "rgba(26, 26, 26, 0.06)",
            borderWidth: 1.25,
            pointRadius: 0,
            tension: 0,
            fill: true,
          },
        ],
      },
      options: (function () {
        var opts = baseOptions();
        opts.scales.x.ticks.callback = function (value) {
          return this.getLabelForValue(value);
        };
        opts.scales.x.title = {
          display: true,
          text: "frequency (cycles / bucket)",
          color: "#5c5a55",
          font: { family: "system-ui, sans-serif", size: 11 },
        };
        opts.scales.y.title = {
          display: true,
          text: "normalized PSD",
          color: "#5c5a55",
          font: { family: "system-ui, sans-serif", size: 11 },
        };
        return opts;
      })(),
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    renderActivity("activity-chart", "activity-payload");
    renderPsd("psd-chart", "psd-payload");
  });
})();
