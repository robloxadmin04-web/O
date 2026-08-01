// Login page logic: validation, SVG icon toggles, theme switch, and the
// real request to /api/login.

(function () {
  "use strict";

  var root = document.documentElement;
  var form = document.getElementById("loginForm");
  var email = document.getElementById("email");
  var password = document.getElementById("password");
  var emailError = document.getElementById("emailError");
  var passwordError = document.getElementById("passwordError");
  var remember = document.getElementById("remember");
  var pwToggle = document.getElementById("pwToggle");
  var submitBtn = document.getElementById("submitBtn");
  var formStatus = document.getElementById("formStatus");
  var themeToggle = document.getElementById("themeToggle");
  var googleBtn = document.getElementById("googleBtn");

  var EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  var EMAIL_KEY = "login.remembered.email";
  var THEME_KEY = "theme";

  // --- Theme ------------------------------------------------------------

  themeToggle.addEventListener("click", function () {
    var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    root.setAttribute("data-theme", next);
    try {
      window.localStorage.setItem(THEME_KEY, next);
    } catch (e) {}
  });

  // --- Remembered email -------------------------------------------------

  var saved = null;
  try {
    saved = window.localStorage.getItem(EMAIL_KEY);
  } catch (e) {
    saved = null;
  }
  if (saved) {
    email.value = saved;
    remember.checked = true;
  }

  // --- Helpers ----------------------------------------------------------

  function setError(input, node, message) {
    node.textContent = message || "";
    if (message) {
      input.classList.add("invalid");
      input.setAttribute("aria-invalid", "true");
    } else {
      input.classList.remove("invalid");
      input.removeAttribute("aria-invalid");
    }
  }

  function setStatus(message) {
    formStatus.textContent = message || "";
  }

  function validateEmail() {
    var value = email.value.trim();
    if (!value) {
      setError(email, emailError, "Email is required.");
      return false;
    }
    if (!EMAIL_PATTERN.test(value)) {
      setError(email, emailError, "Enter a valid email address.");
      return false;
    }
    setError(email, emailError, "");
    return true;
  }

  function validatePassword() {
    if (!password.value) {
      setError(password, passwordError, "Password is required.");
      return false;
    }
    setError(password, passwordError, "");
    return true;
  }

  function setLoading(isLoading) {
    submitBtn.disabled = isLoading;
    if (isLoading) {
      submitBtn.classList.add("loading");
      submitBtn.querySelector(".btn__label").textContent = "Signing in";
    } else {
      submitBtn.classList.remove("loading");
      submitBtn.querySelector(".btn__label").textContent = "Sign in";
    }
  }

  function signIn(payload) {
    return fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload)
    }).then(function (res) {
      return res
        .json()
        .catch(function () {
          return {};
        })
        .then(function (data) {
          if (!res.ok) {
            throw new Error(data.error || "Sign in failed. Please try again.");
          }
          return data;
        });
    });
  }

  // --- Password visibility ---------------------------------------------

  pwToggle.addEventListener("click", function () {
    var isHidden = password.type === "password";
    password.type = isHidden ? "text" : "password";
    pwToggle.classList.toggle("is-visible", isHidden);
    pwToggle.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
    password.focus();
  });

  // --- Field feedback ---------------------------------------------------

  email.addEventListener("blur", validateEmail);
  password.addEventListener("blur", validatePassword);

  email.addEventListener("input", function () {
    if (emailError.textContent) {
      validateEmail();
    }
  });

  password.addEventListener("input", function () {
    if (passwordError.textContent) {
      validatePassword();
    }
  });

  // Placeholder until an OAuth route exists on the server.
  if (googleBtn) {
    googleBtn.addEventListener("click", function () {
      setStatus("Google sign-in is not configured yet.");
    });
  }

  // --- Submit -----------------------------------------------------------

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    setStatus("");

    var okEmail = validateEmail();
    var okPassword = validatePassword();

    if (!okEmail) {
      email.focus();
      return;
    }
    if (!okPassword) {
      password.focus();
      return;
    }

    try {
      if (remember.checked) {
        window.localStorage.setItem(EMAIL_KEY, email.value.trim());
      } else {
        window.localStorage.removeItem(EMAIL_KEY);
      }
    } catch (e) {
      // Storage can be blocked; sign-in still works without it.
    }

    setLoading(true);

    signIn({ email: email.value.trim(), password: password.value })
      .then(function (data) {
        setStatus("Signed in. Redirecting...");
        window.location.href = data.redirect || "/dashboard";
      })
      .catch(function (err) {
        setStatus(err.message);
        setLoading(false);
        password.select();
      });
  });
})();
