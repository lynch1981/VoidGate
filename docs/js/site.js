(function () {
    var header = document.querySelector(".site-header");
    var toggle = document.querySelector(".nav-toggle");
    var nav = document.getElementById("site-nav");
    var page = (location.pathname.split("/").pop() || "index.html");

    if (page === "" || page === "/") {
        page = "index.html";
    }

    if (nav) {
        Array.prototype.forEach.call(nav.querySelectorAll("a[href]"), function (a) {
            var href = a.getAttribute("href");

            if (href === page) {
                a.setAttribute("aria-current", "page");
            }
        });
    }

    if (toggle && header) {
        toggle.addEventListener("click", function () {
            var open = header.classList.toggle("is-open");

            toggle.setAttribute("aria-expanded", open ? "true" : "false");
            toggle.textContent = open ? "Close" : "Menu";
        });
    }

    document.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".copy");
        var block;
        var text;

        if (!btn) {
            return;
        }

        block = btn.closest(".code");

        if (!block) {
            return;
        }

        text = block.querySelector("pre").innerText;

        function ok() {
            var prev = btn.textContent;

            btn.textContent = "Copied";
            btn.classList.add("is-copied");
            setTimeout(function () {
                btn.textContent = prev;
                btn.classList.remove("is-copied");
            }, 1400);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(ok, function () {
                btn.textContent = "Copy failed";
            });
        } else {
            ok();
        }
    });
}());
