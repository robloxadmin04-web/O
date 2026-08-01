// Simple client-side login page logic.
// Replace the fakeSignIn() call with a real request to your backend.

(function () {
  "use strict";

  var form = document.getElementById("loginForm");
  var email = document.getElementById("email");
  var password = document.getElementById("password");
  var emailError = document.getElementById("emailError");
  var passwordError = document.getElementById("passwordError");
  var remember = document.getElementById("remember");
  var pwToggle = document.getElementById("pwToggle");
  var submitBtn = document.getElementById("submitBtn");
  var formStatus = document.getElementById("formStatus");

  var EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  var STORAGE_KEY = "login.remembered.email";

  // Restore a remembered email on load.
  var saved = null;
  try {
    saved = window.localStorage.getItem(STORAGE_KEY);
  } catch (e) {
    saved = null;
  }
  if (saved) {
    email.value = saved;
    remember.checked = true;
  }

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

  function setStatus(message, isError) {
    formStatus.textContent = message || "";
    if (isError) {
      formStatus.classList.add("error");
    } else {
      formStatus.classList.remove("error");
    }
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
    var value = password.value;
    if (!value) {
      setError(password, passwordError, "Password is required.");
      return false;
    }
    if (value.length < 8) {
      setError(password, passwordError, "Password must be at least 8 characters.");
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

  // Stand-in for a real API call. Swap this out for fetch() against your endpoint.
  function fakeSignIn(payload) {
    return new Promise(function (resolve, reject) {
      window.setTimeout(function () {
        if (payload.password === "wrongpassword") {
          reject(new Error("Incorrect email or password."));
        } else {
          resolve({ ok: true });
        }
      }, 1200);
    });
  }

  pwToggle.addEventListener("click", function () {
    var isHidden = password.type === "password";
    password.type = isHidden ? "text" : "password";
    pwToggle.textContent = isHidden ? "Hide" : "Show";
    pwToggle.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
    password.focus();
  });

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
        window.localStorage.setItem(STORAGE_KEY, email.value.trim());
      } else {
        window.localStorage.removeItem(STORAGE_KEY);
      }
    } catch (e) {
      // Storage can be blocked; sign-in still works without it.
    }

    setLoading(true);

    fakeSignIn({ email: email.value.trim(), password: password.value })
      .then(function () {
        setStatus("Signed in successfully. Redirecting...", false);
        // window.location.href = "/dashboard";
      })
      .catch(function (err) {
        setStatus(err.message, true);
        password.select();
      })
      .then(function () {
        setLoading(false);
      });
  });
})();
