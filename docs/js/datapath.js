(function () {
    var root = document.querySelector("[data-gate]");

    if (!root) {
        return;
    }

    var lane = root.querySelector(".datapath-lane");
    var armedEl = root.querySelector("[data-m='armed']");
    var rxEl = root.querySelector("[data-m='rx']");
    var passEl = root.querySelector("[data-m='passed']");
    var dropEl = root.querySelector("[data-m='dropped']");
    var tabs = root.querySelectorAll(".seg button");
    var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var armed = false;
    var rx = 0;
    var passed = 0;
    var dropped = 0;
    var packets = [];
    var lastSpawn = 0;
    var running = false;

    function fmt(n) {
        return String(n);
    }

    function paintMetrics() {
        armedEl.textContent = armed ? "1" : "0";
        rxEl.textContent = fmt(rx);
        passEl.textContent = fmt(passed);
        dropEl.textContent = fmt(dropped);
    }

    function setArmed(next) {
        armed = next;
        root.dataset.armed = next ? "1" : "0";
        Array.prototype.forEach.call(tabs, function (btn) {
            var on = btn.getAttribute("data-arm") === (next ? "1" : "0");

            btn.setAttribute("aria-selected", on ? "true" : "false");
        });
        paintMetrics();
    }

    function centerOf(name) {
        var el = root.querySelector('[data-stage="' + name + '"]');
        var r;
        var lr;

        if (!el || !lane) {
            return null;
        }

        r = el.getBoundingClientRect();
        lr = lane.getBoundingClientRect();

        return {
            x: r.left - lr.left + r.width / 2,
            y: r.top - lr.top + r.height / 2
        };
    }

    function pathFor(willDrop) {
        var names;
        var pts = [];
        var i;
        var p;

        if (!armed) {
            names = ["nic", "rx", "pass"];
        } else if (willDrop) {
            names = ["nic", "rx", "parse", "allow", "drop", "dropv"];
        } else {
            names = ["nic", "rx", "parse", "allow", "drop", "count", "pass"];
        }

        for (i = 0; i < names.length; i++) {
            p = centerOf(names[i]);

            if (p) {
                pts.push(p);
            }
        }

        return pts;
    }

    function spawn(now) {
        var willDrop = armed && Math.random() < 0.34;
        var pts = pathFor(willDrop);
        var el;

        if (pts.length < 2) {
            return;
        }

        rx += 1;
        el = document.createElement("span");
        el.className = "pkt" + (willDrop ? " is-drop" : "");
        el.setAttribute("aria-hidden", "true");
        el.style.transform = "translate(" + pts[0].x + "px," + pts[0].y + "px)";
        lane.appendChild(el);
        packets.push({
            el: el,
            pts: pts,
            t0: now,
            dur: armed ? 1400 : 900,
            drop: willDrop,
            done: false
        });
        paintMetrics();
    }

    function lerp(a, b, t) {
        return a + (b - a) * t;
    }

    function at(pts, u) {
        var n = pts.length - 1;
        var x = u * n;
        var i = Math.min(n - 1, Math.floor(x));
        var t = x - i;

        return {
            x: lerp(pts[i].x, pts[i + 1].x, t),
            y: lerp(pts[i].y, pts[i + 1].y, t)
        };
    }

    function tick(now) {
        var interval = armed ? 180 : 420;
        var i;
        var p;
        var u;
        var pos;

        if (!running) {
            return;
        }

        if (!reduced && now - lastSpawn >= interval) {
            spawn(now);
            lastSpawn = now;
        }

        for (i = packets.length - 1; i >= 0; i--) {
            p = packets[i];
            u = (now - p.t0) / p.dur;

            if (u >= 1) {
                if (!p.done) {
                    if (p.drop) {
                        dropped += 1;
                    } else {
                        passed += 1;
                    }

                    p.done = true;
                    paintMetrics();
                }

                p.el.remove();
                packets.splice(i, 1);
                continue;
            }

            pos = at(p.pts, u);
            p.el.style.transform = "translate(" + pos.x + "px," + pos.y + "px)";
        }

        requestAnimationFrame(tick);
    }

    Array.prototype.forEach.call(tabs, function (btn) {
        btn.addEventListener("click", function () {
            setArmed(btn.getAttribute("data-arm") === "1");
        });
    });

    root.addEventListener("keydown", function (ev) {
        if (ev.key === "i" || ev.key === "I") {
            setArmed(false);
        }

        if (ev.key === "a" || ev.key === "A") {
            setArmed(true);
        }
    });

    setArmed(false);
    running = true;

    if (reduced) {
        paintMetrics();
        return;
    }

    requestAnimationFrame(function (now) {
        lastSpawn = now;
        tick(now);
    });
}());
