"use strict";

const API = "/api/v1";
const PAGE_SIZE = 25;
const SEVERITY_LABEL = { critical: "Critica", high: "Alta", medium: "Media", low: "Baja" };
const SEVERITY_COLORS = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6" };
const RISK_LABELS = { clean: "Limpio", suspicious: "Sospechoso", investigate: "Investigar", compromised: "Comprometido" };
const RISK_COLORS = { clean: "#22c55e", suspicious: "#eab308", investigate: "#f97316", compromised: "#ef4444" };
const TITLES = { overview: "Resumen", alerts: "Alertas", agents: "Agentes", events: "Eventos", rules: "Reglas", agent_detail: "Detalle de agente" };

let token = sessionStorage.getItem("wolffy_token") || "";
let currentName = null;
let current = null;
let lastAlertCount = null;
let searchTimeout = null;

// ── DOM helpers ──
function h(tag, props, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
        if (v === null || v === undefined || v === false) continue;
        if (k === "class") el.className = v;
        else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat(Infinity)) {
        if (c === null || c === undefined || c === false) continue;
        if (c instanceof Node) el.appendChild(c);
        else el.appendChild(document.createTextNode(String(c)));
    }
    return el;
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

// ── API ──
async function api(path, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    if (token) headers.Authorization = "Bearer " + token;
    const r = await fetch(API + path, Object.assign({}, opts, { headers }));
    if (r.status === 401) { showLogin(Boolean(token)); throw new Error("auth"); }
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
}

// ── Formatters ──
function fmtTime(iso) { return iso ? new Date(iso).toLocaleString() : "-"; }
function ago(iso) {
    if (!iso) return "nunca";
    const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (s < 60) return s + "s";
    if (s < 3600) return Math.round(s / 60) + "m";
    if (s < 86400) return Math.round(s / 3600) + "h";
    return Math.round(s / 86400) + "d";
}
function sevBadge(sev) {
    return h("span", {
        class: "badge " + sev,
        style: "cursor: pointer",
        title: "Filtrar por severidad",
        onclick: (e) => {
            e.stopPropagation();
            views.alerts.state.severity = sev;
            views.alerts.state.offset = 0;
            show("alerts");
        }
    }, SEVERITY_LABEL[sev] || sev);
}
function riskBadge(level) { return h("span", { class: "badge " + (level || "clean") }, RISK_LABELS[level] || level); }

function summarize(ev) {
    const d = ev.data || {};
    switch (ev.event_type) {
        case "process_start": return (d.name || "?") + " (PID " + d.pid + ")" + (d.cmdline ? "  " + d.cmdline : "");
        case "file_event": return (d.action || "?") + "  " + (d.path || "");
        case "network_connect": return (d.process_name || "?") + " → " + d.remote_ip + ":" + d.remote_port;
        case "listening_port": return (d.process_name || "?") + " escuchando en :" + d.port;
        default: return JSON.stringify(d).slice(0, 200);
    }
}

// ── Widgets ──
function table(headers, rows, emptyText) {
    if (!rows.length) return h("div", { class: "empty" }, emptyText);
    return h("div", { class: "table-wrap" },
        h("table", null,
            h("thead", null, h("tr", null, headers.map(t => h("th", null, t)))),
            h("tbody", null, rows)));
}
function pager(state, total, fn) {
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const page = Math.floor(state.offset / PAGE_SIZE) + 1;
    return h("div", { class: "pager" },
        h("span", { class: "muted" }, total + " resultados · pág " + page + "/" + pages),
        h("button", { class: "btn small", disabled: page <= 1, onclick: () => { state.offset -= PAGE_SIZE; fn(); } }, "← Ant"),
        h("button", { class: "btn small", disabled: page >= pages, onclick: () => { state.offset += PAGE_SIZE; fn(); } }, "Sig →"));
}
function sel(options, value, fn) {
    const node = h("select", { onchange: () => fn(node.value) },
        options.map(([v, l]) => h("option", { value: v }, l)));
    node.value = value;
    return node;
}
function kpi(label, value, sub, cls) {
    return h("div", { class: "card kpi " + (cls || "") },
        h("div", { class: "kpi-label" }, label),
        h("div", { class: "kpi-value" }, String(value)),
        sub ? h("div", { class: "kpi-sub" }, sub) : null);
}

// ── Canvas Charts ──
function drawBarChart(canvas, data) {
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    const W = rect.width, H = rect.height;
    const pad = { top: 10, right: 10, bottom: 28, left: 35 };
    const chartW = W - pad.left - pad.right;
    const chartH = H - pad.top - pad.bottom;
    if (!data.length) { ctx.fillStyle = "#7d8694"; ctx.font = "12px system-ui"; ctx.textAlign = "center"; ctx.fillText("Sin datos", W/2, H/2); return; }
    const maxVal = Math.max(1, ...data.map(d => d.total));
    const barW = Math.max(4, Math.min(20, chartW / data.length - 2));
    ctx.clearRect(0, 0, W, H);
    // Grid lines
    ctx.strokeStyle = "rgba(255,255,255,.06)"; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) { const y = pad.top + chartH * (1 - i/4); ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(W - pad.right, y); ctx.stroke(); ctx.fillStyle = "#7d8694"; ctx.font = "10px system-ui"; ctx.textAlign = "right"; ctx.fillText(String(Math.round(maxVal * i / 4)), pad.left - 6, y + 3); }
    // Bars
    data.forEach((d, i) => {
        const x = pad.left + (i / data.length) * chartW + (chartW / data.length - barW) / 2;
        const sevs = ["low", "medium", "high", "critical"];
        let y = pad.top + chartH;
        sevs.forEach(s => {
            const val = d[s] || 0; if (!val) return;
            const h = (val / maxVal) * chartH;
            y -= h;
            ctx.fillStyle = SEVERITY_COLORS[s]; ctx.beginPath(); ctx.roundRect(x, y, barW, h, [2,2,0,0]); ctx.fill();
        });
        // X label
        if (i % Math.max(1, Math.floor(data.length / 8)) === 0) {
            const t = d.timestamp ? new Date(d.timestamp).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}) : "";
            ctx.fillStyle = "#7d8694"; ctx.font = "10px system-ui"; ctx.textAlign = "center"; ctx.fillText(t, x + barW/2, H - 6);
        }
    });
}

function drawLineChart(canvas, data, keys, colors, labels) {
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    const W = rect.width, H = rect.height;
    const pad = { top: 10, right: 10, bottom: 28, left: 35 };
    const chartW = W - pad.left - pad.right;
    const chartH = H - pad.top - pad.bottom;
    if (!data.length) { ctx.fillStyle = "#7d8694"; ctx.font = "12px system-ui"; ctx.textAlign = "center"; ctx.fillText("Sin datos", W/2, H/2); return; }
    ctx.clearRect(0, 0, W, H);
    // Grid
    ctx.strokeStyle = "rgba(255,255,255,.06)"; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) { const y = pad.top + chartH * (1 - i/4); ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(W - pad.right, y); ctx.stroke(); ctx.fillStyle = "#7d8694"; ctx.font = "10px system-ui"; ctx.textAlign = "right"; ctx.fillText(Math.round(25*i) + "%", pad.left - 6, y + 3); }
    // Lines
    keys.forEach((key, ki) => {
        ctx.strokeStyle = colors[ki]; ctx.lineWidth = 1.5; ctx.beginPath();
        data.forEach((d, i) => {
            const x = pad.left + (i / Math.max(1, data.length - 1)) * chartW;
            const y = pad.top + chartH * (1 - (d[key] || 0) / 100);
            i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
        });
        ctx.stroke();
    });
    // X labels
    [0, Math.floor(data.length / 2), data.length - 1].forEach(i => {
        if (i >= data.length) return;
        const x = pad.left + (i / Math.max(1, data.length - 1)) * chartW;
        const t = data[i].timestamp ? new Date(data[i].timestamp).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}) : "";
        ctx.fillStyle = "#7d8694"; ctx.font = "10px system-ui"; ctx.textAlign = "center"; ctx.fillText(t, x, H - 6);
    });
    // Legend
    let lx = pad.left;
    keys.forEach((key, ki) => {
        ctx.fillStyle = colors[ki]; ctx.fillRect(lx, 2, 10, 3); ctx.fillStyle = "#7d8694"; ctx.font = "10px system-ui"; ctx.textAlign = "left"; ctx.fillText(labels[ki], lx + 14, 8); lx += ctx.measureText(labels[ki]).width + 26;
    });
}

function drawGauge(svg, score, level) {
    const color = RISK_COLORS[level] || "#7d8694";
    const pct = Math.min(score, 100) / 100;
    // Arc from 180° to 0° (left to right semicircle)
    const cx = 60, cy = 60, r = 50;
    const startAngle = Math.PI;
    const endAngle = Math.PI - (pct * Math.PI);
    const x1 = cx + r * Math.cos(startAngle), y1 = cy + r * Math.sin(startAngle);
    const x2 = cx + r * Math.cos(endAngle), y2 = cy + r * Math.sin(endAngle);
    const large = pct > 0.5 ? 1 : 0;
    svg.innerHTML = `
        <path d="M ${cx-r} ${cy} A ${r} ${r} 0 0 1 ${cx+r} ${cy}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="8" stroke-linecap="round"/>
        ${pct > 0.01 ? `<path d="M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round" style="filter: drop-shadow(0 0 4px ${color}40)"/>` : ""}
        <text x="${cx}" y="${cy - 6}" text-anchor="middle" fill="${color}" font-size="20" font-weight="800">${score}</text>
        <text x="${cx}" y="${cy + 10}" text-anchor="middle" fill="#7d8694" font-size="9" text-transform="uppercase" font-weight="700">${(RISK_LABELS[level] || level).toUpperCase()}</text>
    `;
}

// ── Toasts ──
function toast(title, msg, severity) {
    const container = document.getElementById("toasts");
    const el = h("div", { class: "toast " + (severity || "") },
        h("div", { class: "toast-body" },
            h("div", { class: "toast-title" }, title),
            h("div", { class: "toast-msg" }, msg)),
        h("button", { class: "toast-close", onclick: () => { el.classList.add("removing"); setTimeout(() => el.remove(), 250); } }, "×"));
    container.prepend(el);
    setTimeout(() => { if (el.parentNode) { el.classList.add("removing"); setTimeout(() => el.remove(), 250); } }, 8000);
}

function beep() {
    try { const ac = new (window.AudioContext || window.webkitAudioContext)(); const o = ac.createOscillator(); const g = ac.createGain(); o.connect(g); g.connect(ac.destination); o.frequency.value = 660; g.gain.value = 0.08; o.start(); o.stop(ac.currentTime + 0.12); } catch(e) {}
}

// ── Alert rows ──
function alertRow(alert, withActions, refresh) {
    const pre = h("pre", { style: "cursor: pointer", title: "Click para copiar" }, JSON.stringify(alert.event, null, 2));
    pre.onclick = (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(pre.textContent).then(() => toast("Copiado", "JSON copiado al portapapeles", "low"));
    };
    const detail = h("tr", { class: "detail", hidden: true },
        h("td", { colspan: withActions ? 7 : 5 }, pre));
    const row = h("tr", { class: "clickable" + (alert.acknowledged ? " acked" : ""), onclick: () => { detail.hidden = !detail.hidden; } },
        h("td", null, sevBadge(alert.severity)),
        h("td", null, alert.rule_name, h("div", { class: "muted mono" }, alert.rule_id)),
        h("td", { class: "mono" }, alert.agent_id),
        h("td", { class: "break" }, alert.message),
        withActions ? h("td", { class: "mono" }, alert.mitre_attack || "-") : null,
        h("td", null, fmtTime(alert.timestamp)),
        withActions ? h("td", null, alert.acknowledged ? h("span", {class: "muted"}, "Aceptada") : h("button", {
            class: "btn small", onclick: async (e) => { e.stopPropagation(); await api("/alerts/" + alert.id + "/ack", { method: "POST" }); refresh(); },
        }, "Aceptar")) : null);
    return [row, detail];
}

// ── Views ──
const views = {
    overview: {
        mount(root) {
            this.kpis = h("div", { class: "kpis" });
            this.chartCard = h("div", { class: "card" }, h("h3", null, "Actividad de alertas (24h)"));
            this.alertsDiv = h("div");
            this.agentsDiv = h("div");
            root.append(
                this.kpis,
                this.chartCard,
                h("div", { class: "grid-2", style: "margin-top:14px" },
                    h("div", { class: "card" }, h("h3", null, "Alertas abiertas recientes"), this.alertsDiv),
                    h("div", { class: "card" }, h("h3", null, "Agentes"), this.agentsDiv)));
        },
        async refresh() {
            const [stats, alerts, agents, timeline] = await Promise.all([
                api("/stats"), api("/alerts?acknowledged=false&limit=8"), api("/agents"), api("/alerts/timeline?hours=24").catch(() => [])
            ]);
            const o = stats.alerts.open_by_severity;
            // Check for new alerts
            const totalOpen = stats.alerts.open;
            if (lastAlertCount !== null && totalOpen > lastAlertCount) {
                const diff = totalOpen - lastAlertCount;
                toast("Nuevas alertas", diff + " alerta(s) sin reconocer", o.critical > 0 ? "critical" : "high");
                if (o.critical > 0) beep();
            }
            lastAlertCount = totalOpen;
            // KPIs
            clear(this.kpis);
            this.kpis.append(
                kpi("Agentes en línea", stats.agents.online, "de " + stats.agents.total + " registrados"),
                kpi("Críticas", o.critical, null, "critical"),
                kpi("Altas", o.high, null, "high"),
                kpi("Medias + Bajas", o.medium + o.low, null, "medium"),
                kpi("Eventos / hora", stats.events.last_hour, stats.alerts.last_24h + " alertas en 24h"));
            // Timeline chart
            clear(this.chartCard);
            this.chartCard.append(h("h3", null, "Actividad de alertas (24h)"));
            const chartDiv = h("div", { class: "chart-container" });
            const canvas = h("canvas", null);
            chartDiv.append(canvas);
            this.chartCard.append(chartDiv);
            requestAnimationFrame(() => drawBarChart(canvas, timeline));
            // Alerts table
            clear(this.alertsDiv);
            this.alertsDiv.append(table(["Nivel", "Regla", "Agente", "Detalle", "Fecha"],
                alerts.items.map(a => alertRow(a, false)), "Sin alertas abiertas."));
            // Agents table
            clear(this.agentsDiv);
            this.agentsDiv.append(table(["Equipo", "Riesgo", "Estado", "Visto"],
                agents.map(a => h("tr", { class: "clickable", onclick: () => showAgentDetail(a.id) },
                    h("td", null, a.hostname || a.id, h("div", { class: "muted mono" }, a.ip_address)),
                    h("td", null, riskBadge(a.risk_level)),
                    h("td", null, h("span", { class: "badge " + a.status }, a.status === "online" ? "En línea" : "Offline")),
                    h("td", { class: "muted" }, ago(a.last_seen)))), "Esperando agentes."));
        },
    },
    alerts: {
        state: { severity: "", status: "open", offset: 0 },
        mount(root) {
            const s = this.state;
            const reload = () => { s.offset = 0; this.refresh(); };
            this.body = h("div");
            root.append(h("div", { class: "toolbar" },
                sel([["", "Todas"], ["critical", "Crítica"], ["high", "Alta"], ["medium", "Media"], ["low", "Baja"]],
                    s.severity, v => { s.severity = v; reload(); }),
                sel([["open", "Abiertas"], ["ack", "Reconocidas"], ["all", "Todas"]],
                    s.status, v => { s.status = v; reload(); }),
                h("span", { class: "spacer" }),
                h("button", { class: "btn danger", onclick: async () => {
                    const q = s.severity ? "?severity=" + s.severity : "";
                    await api("/alerts/ack-all" + q, { method: "POST" }); this.refresh();
                } }, "Reconocer todas")), this.body);
        },
        async refresh() {
            const s = this.state;
            const p = new URLSearchParams({ limit: PAGE_SIZE, offset: s.offset });
            if (s.severity) p.set("severity", s.severity);
            if (s.status === "open") p.set("acknowledged", "false");
            if (s.status === "ack") p.set("acknowledged", "true");
            const data = await api("/alerts?" + p);
            clear(this.body);
            this.body.append(
                h("div", { class: "card" }, table(["Nivel", "Regla", "Agente", "Detalle", "MITRE", "Fecha", ""],
                    data.items.map(a => alertRow(a, true, () => this.refresh())), "Sin alertas.")),
                pager(s, data.total, () => this.refresh()));
        },
    },
    agents: {
        mount(root) { this.body = h("div", { class: "card" }); root.append(this.body); },
        async refresh() {
            const agents = await api("/agents");
            clear(this.body);
            this.body.append(table(
                ["ID", "Equipo", "IP", "SO", "Versión", "Riesgo", "Estado", "Visto", "Alertas"],
                agents.map(a => h("tr", { class: "clickable", onclick: () => showAgentDetail(a.id) },
                    h("td", { class: "mono" }, a.id),
                    h("td", null, a.hostname),
                    h("td", { class: "mono" }, a.ip_address),
                    h("td", null, a.os_info),
                    h("td", null, a.version),
                    h("td", null, riskBadge(a.risk_level)),
                    h("td", null, h("span", { class: "badge " + a.status }, a.status === "online" ? "En línea" : "Offline")),
                    h("td", { class: "muted" }, ago(a.last_seen)),
                    h("td", null, String(a.open_alerts)))), "Sin agentes."));
        },
    },
    events: {
        state: { type: "", offset: 0 },
        mount(root) {
            const s = this.state;
            this.body = h("div");
            root.append(h("div", { class: "toolbar" },
                sel([["", "Todos"], ["process_start", "Procesos"], ["file_event", "Archivos"], ["network_connect", "Red"], ["listening_port", "Puertos"]],
                    s.type, v => { s.type = v; s.offset = 0; this.refresh(); })), this.body);
        },
        async refresh() {
            const s = this.state;
            const p = new URLSearchParams({ limit: PAGE_SIZE, offset: s.offset });
            if (s.type) p.set("event_type", s.type);
            const data = await api("/events?" + p);
            clear(this.body);
            this.body.append(
                h("div", { class: "card" }, table(["Fecha", "Agente", "Tipo", "Detalle"],
                    data.items.map(e => h("tr", null,
                        h("td", null, fmtTime(e.timestamp)),
                        h("td", { class: "mono" }, e.agent_id),
                        h("td", null, h("span", { class: "badge neutral" }, e.event_type)),
                        h("td", { class: "break mono" }, summarize(e)))), "Sin eventos.")),
                pager(s, data.total, () => this.refresh()));
        },
    },
    rules: {
        mount(root) { this.body = h("div", { class: "card" }); root.append(this.body); },
        async refresh() {
            const data = await api("/rules");
            clear(this.body);
            if (data.errors.length) this.body.append(h("p", { class: "error" }, data.errors.length + " reglas con errores: " + data.errors.join("; ")));
            this.body.append(table(["ID", "Nombre", "Nivel", "Evento", "Plataformas", "MITRE", "Activa"],
                data.items.map(r => h("tr", null,
                    h("td", { class: "mono" }, r.id),
                    h("td", null, r.name, h("div", { class: "muted" }, r.description)),
                    h("td", null, sevBadge(r.severity)),
                    h("td", { class: "mono" }, r.event_type),
                    h("td", null, r.platforms.length ? r.platforms.join(", ") : "todas"),
                    h("td", { class: "mono" }, r.mitre || "-"),
                    h("td", null, r.enabled ? "Sí" : "No"))), "Sin reglas."));
        },
    },
    agent_detail: {
        agentId: null,
        mount(root) {
            this.header = h("div", { class: "agent-detail" });
            this.metricsCard = h("div", { class: "card" }, h("h3", null, "Métricas del sistema"));
            this.alertsCard = h("div", { class: "card" }, h("h3", null, "Alertas recientes"));
            root.append(
                h("div", { style: "margin-bottom:14px" },
                    h("button", { class: "btn small", onclick: () => show("agents") }, "← Volver a agentes")),
                this.header,
                h("div", { class: "grid-2", style: "margin-top:14px" }, this.metricsCard, this.alertsCard));
        },
        async refresh() {
            const id = this.agentId;
            if (!id) return;
            const [agent, metrics, alerts, risk] = await Promise.all([
                api("/agents/" + id), api("/agents/" + id + "/metrics?limit=60"),
                api("/alerts?agent_id=" + id + "&limit=10"), api("/agents/" + id + "/risk").catch(() => ({score:0,level:"clean"}))
            ]);
            // Header
            clear(this.header);
            const infoCard = h("div", { class: "card" },
                h("h3", null, "Información"),
                ...[['Hostname', agent.hostname], ['ID', agent.id], ['IP', agent.ip_address],
                    ['SO', agent.os_info], ['Versión', agent.version],
                    ['Estado', agent.status], ['Primera vez', fmtTime(agent.first_seen)],
                    ['Última vez', fmtTime(agent.last_seen)]]
                    .map(([l,v]) => h("div", { class: "agent-info-row" }, h("span", { class: "label" }, l), h("span", { class: "mono" }, v || "-"))));
            const gaugeCard = h("div", { class: "card" },
                h("h3", null, "Nivel de riesgo"),
                h("div", { class: "gauge-wrap" }));
            const gaugeSvg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
            gaugeSvg.setAttribute("viewBox", "0 0 120 70");
            gaugeSvg.classList.add("gauge-svg");
            gaugeCard.querySelector(".gauge-wrap").append(gaugeSvg);
            drawGauge(gaugeSvg, risk.score, risk.level);
            this.header.append(infoCard, gaugeCard);
            // Metrics chart
            clear(this.metricsCard);
            this.metricsCard.append(h("h3", null, "Métricas del sistema"));
            const chartDiv = h("div", { class: "chart-container" });
            const canvas = h("canvas", null);
            chartDiv.append(canvas);
            this.metricsCard.append(chartDiv);
            requestAnimationFrame(() => drawLineChart(canvas, metrics, ["cpu", "memory", "disk"], ["#3fb6a8", "#3b82f6", "#f97316"], ["CPU", "RAM", "Disco"]));
            // Alerts
            clear(this.alertsCard);
            this.alertsCard.append(h("h3", null, "Alertas recientes"));
            this.alertsCard.append(table(["Nivel", "Regla", "Mensaje", "Fecha"],
                alerts.items.map(a => h("tr", null,
                    h("td", null, sevBadge(a.severity)),
                    h("td", null, a.rule_name),
                    h("td", { class: "break" }, a.message),
                    h("td", null, fmtTime(a.timestamp)))), "Sin alertas."));
        },
    },
};

function showAgentDetail(agentId) {
    views.agent_detail.agentId = agentId;
    show("agent_detail");
}

// ── Navigation ──
function setConnection(ok) {
    const n = document.getElementById("conn");
    n.className = "conn " + (ok ? "ok" : "bad");
    n.textContent = ok ? "Conectado" : "Sin conexión";
}

async function refreshCurrent() {
    if (!current) return;
    try {
        await current.refresh();
        setConnection(true);
        document.getElementById("updated").textContent = new Date().toLocaleTimeString();
    } catch (e) { if (e.message !== "auth") setConnection(false); }
}

function show(name) {
    if (!views[name]) name = "overview";
    currentName = name;
    current = views[name];
    if (name !== "agent_detail") location.hash = name;
    document.getElementById("title").textContent = TITLES[name] || name;
    document.querySelectorAll(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.view === name));
    const root = document.getElementById("view");
    clear(root);
    current.mount(root);
    refreshCurrent();
    // Close mobile sidebar
    document.getElementById("sidebar").classList.remove("open");
}

function showLogin(failed) {
    document.getElementById("login").hidden = false;
    document.getElementById("login-error").hidden = !failed;
    document.getElementById("token-input").focus();
}

// ── Search ──
function doSearch(q) {
    const overlay = document.getElementById("search-results");
    if (!q || q.length < 2) { overlay.hidden = true; return; }
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(async () => {
        try {
            const data = await api("/search?q=" + encodeURIComponent(q));
            clear(overlay);
            overlay.hidden = false;
            if (!data.alerts.length && !data.events.length) {
                overlay.append(h("div", { class: "empty" }, "Sin resultados para '" + q + "'"));
                return;
            }
            if (data.alerts.length) {
                overlay.append(h("h4", null, "Alertas (" + data.alerts.length + ")"));
                data.alerts.forEach(a => overlay.append(
                    h("div", { class: "search-hit", onclick: () => { overlay.hidden = true; show("alerts"); } },
                        sevBadge(a.severity), " ", a.rule_name, " — ", h("span", { class: "hit-label" }, a.message.slice(0, 100)))));
            }
            if (data.events.length) {
                overlay.append(h("h4", null, "Eventos (" + data.events.length + ")"));
                data.events.forEach(e => overlay.append(
                    h("div", { class: "search-hit", onclick: () => { overlay.hidden = true; show("events"); } },
                        h("span", { class: "badge neutral" }, e.event_type), " ", h("span", { class: "hit-label" }, summarize(e).slice(0, 100)))));
            }
        } catch (e) { overlay.hidden = true; }
    }, 350);
}

// ── Init ──
document.getElementById("nav").addEventListener("click", e => {
    const b = e.target.closest(".nav-item");
    if (b) show(b.dataset.view);
});
document.getElementById("refresh").addEventListener("click", refreshCurrent);
document.getElementById("purge-btn").addEventListener("click", async () => {
    if (confirm("¿Estás seguro de que deseas eliminar TODOS los datos (agentes, eventos, alertas)? Esta acción no se puede deshacer.")) {
        try {
            await api("/purge", { method: "POST" });
            toast("Éxito", "Base de datos limpiada correctamente", "low");
            refreshCurrent();
        } catch (e) {
            toast("Error", "No se pudo limpiar la base de datos", "critical");
        }
    }
});
document.getElementById("login-form").addEventListener("submit", e => {
    e.preventDefault();
    token = document.getElementById("token-input").value.trim();
    sessionStorage.setItem("wolffy_token", token);
    document.getElementById("login").hidden = true;
    refreshCurrent();
});
document.getElementById("menu-toggle").addEventListener("click", () => {
    document.getElementById("sidebar").classList.toggle("open");
});
document.getElementById("search-input").addEventListener("input", e => doSearch(e.target.value.trim()));
document.getElementById("search-input").addEventListener("focus", e => { if (e.target.value.trim().length >= 2) doSearch(e.target.value.trim()); });
document.addEventListener("click", e => {
    if (!e.target.closest(".search-box") && !e.target.closest(".search-overlay"))
        document.getElementById("search-results").hidden = true;
});

setInterval(() => {
    if (!document.hidden && document.getElementById("login").hidden) refreshCurrent();
}, 5000);

show(location.hash.slice(1) || "overview");
