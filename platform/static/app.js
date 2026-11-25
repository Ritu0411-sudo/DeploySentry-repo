/* AstraTravel portal — plain JavaScript that calls the same API the
   DeploySentry agent tests. The route strings below are deliberately written
   out in full: the Discovery Agent finds the API surface by reading this
   file, exactly as the TBO problem statement describes ("reading front-end
   JavaScript for API routes").

   One route is NOT written out in full on purpose: the supplier-sync call
   below assembles its URL from parts at runtime, so a plain text search of
   this file never finds it. That is the shadow API (see app.py flaw #7). */

let token = null;
let myAgency = null;

async function api(method, path, body) {
  const res = await fetch(path, {
    method: method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "Authorization": "Bearer " + token } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

async function doLogin() {
  const data = await api("POST", "/auth/login", {
    username: document.getElementById("username").value,
    password: document.getElementById("password").value,
  });
  if (data.access_token) {
    token = data.access_token;
    myAgency = data.user.agency_id;
    document.getElementById("login-status").textContent =
      "Logged in as " + data.user.username + " (" + data.user.role +
      ", " + (myAgency || "platform") + ")";
  } else {
    document.getElementById("login-status").textContent =
      "Login failed: " + JSON.stringify(data);
  }
}

async function doSearch() {
  const from = document.getElementById("from").value;
  const to = document.getElementById("to").value;
  const date = document.getElementById("date").value;
  const data = await api("GET",
    "/search/flights?from=" + from + "&to=" + to + "&date=" + date);
  const list = document.getElementById("flights");
  list.innerHTML = "";
  (data.results || []).forEach(function (f) {
    const li = document.createElement("li");
    li.textContent = f.flight_id + ": " + f.from + " → " + f.to +
      " — base fare Rs. " + f.base_fare;
    li.onclick = function () {
      document.getElementById("flight-id").value = f.flight_id;
    };
    list.appendChild(li);
  });
  // Keep supplier inventory fresh in the background (shadow API call —
  // the URL is assembled at runtime, so it never appears as one string here).
  const syncParts = ["/internal", "supplier-sync"];
  api("POST", syncParts.join("/"), { supplier: "amadeus", inventory: [] });
}

async function doHold() {
  const data = await api("POST", "/bookings/hold", {
    flight_id: document.getElementById("flight-id").value,
    travellers: parseInt(document.getElementById("pax").value, 10),
  });
  window._holdId = data.hold_id;
  document.getElementById("hold-status").textContent =
    "Hold: " + data.hold_id + " — estimated fare Rs. " + data.fare_estimate;
  document.getElementById("total").value = data.fare_estimate;
}

async function doBook() {
  const data = await api("POST", "/bookings", {
    hold_id: window._holdId,
    total: parseInt(document.getElementById("total").value, 10),
  });
  document.getElementById("book-status").textContent =
    "Booked: " + data.id + " — total Rs. " + data.total +
    " (" + data.status + ")";
  document.getElementById("booking-id").value = data.id;
}

async function doGetBooking() {
  const id = document.getElementById("booking-id").value;
  const data = await api("GET", "/bookings/" + id);
  document.getElementById("booking-view").textContent =
    JSON.stringify(data, null, 2);
}

async function doPay() {
  const id = document.getElementById("booking-id").value;
  const booking = await api("GET", "/bookings/" + id);
  const data = await api("POST", "/bookings/" + id + "/pay",
    { amount: booking.total, method: "card" });
  document.getElementById("booking-view").textContent =
    JSON.stringify(data, null, 2);
}

async function doCancel() {
  const id = document.getElementById("booking-id").value;
  const data = await api("POST", "/bookings/" + id + "/cancel",
    { reason: "traveller request" });
  document.getElementById("booking-view").textContent =
    JSON.stringify(data, null, 2);
}

async function doCoupon() {
  const id = document.getElementById("booking-id").value;
  const data = await api("POST", "/coupons/apply", {
    code: document.getElementById("coupon").value,
    booking_id: id,
  });
  document.getElementById("booking-view").textContent =
    JSON.stringify(data, null, 2);
}

async function doListBookings() {
  const data = await api("GET", "/bookings?agency_id=" + myAgency);
  const list = document.getElementById("my-bookings");
  list.innerHTML = "";
  (data.bookings || []).forEach(function (b) {
    const li = document.createElement("li");
    li.textContent = b.id + " — " + b.flight_id + " — Rs. " + b.total +
      " — " + b.status;
    li.onclick = function () {
      document.getElementById("booking-id").value = b.id;
      doGetBooking();
    };
    list.appendChild(li);
  });
}

// Show the deployed version in the footer.
fetch("/demo/releases")
  .then(function (r) { return r.json(); })
  .then(function (d) {
    document.getElementById("version").textContent = d.current_version;
  });
