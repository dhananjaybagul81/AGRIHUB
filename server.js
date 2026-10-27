"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { promisify } = require("node:util");

const ROOT = __dirname;
const STORE_FILE = path.join(ROOT, "farmora-store-fixed", "product.html");
const UPI_QR_FILE = path.join(ROOT, "farmora-store-fixed", "assets", "upi-payment-qr.jpg");
const DATA_DIRECTORY = process.env.DATA_DIR || path.join(ROOT, "data");
const ORDERS_FILE = path.join(DATA_DIRECTORY, "orders.json");
const USERS_FILE = path.join(DATA_DIRECTORY, "users.json");
const CUSTOM_PRODUCTS_FILE = path.join(DATA_DIRECTORY, "products.json");
const MAX_BODY_BYTES = 16 * 1024;
const MAX_QUANTITY = 20;
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24;
const SESSION_COOKIE = "agrihub_session";
const PAYMENT_METHODS = Object.freeze(["upi", "card", "netbanking", "cod"]);
const PRODUCT_CATEGORIES = Object.freeze(["Organic", "NPK", "Urea & DAP", "Micronutrients", "Potash", "Specialty", "Pesticides"]);
const UPI_ID_PATTERN = /^[a-zA-Z0-9._-]{2,256}@[a-zA-Z][a-zA-Z0-9.-]{1,63}$/;
const PRODUCTS = Object.freeze({
  "organic-compost": { name: "EarthKind Organic Compost", price: 649 },
  "npk-balanced": { name: "FieldBalance NPK Fertilizer", price: 489 },
  "seaweed-tonic": { name: "RootRise Seaweed Plant Tonic", price: 799 },
  "urea-fertilizer": { name: "FarmStart Urea Fertilizer", price: 359 },
  "dap-fertilizer": { name: "FieldStart DAP Fertilizer", price: 429 },
  vermicompost: { name: "SoilSong Vermicompost Blend", price: 429 },
  "micronutrient-mix": { name: "TracePlus Micro Nutrient Mix", price: 599 },
  "magnesium-sulphate": { name: "MagGrow Magnesium Sulphate", price: 449 },
  "mop-potash": { name: "HarvestPro MOP Potash", price: 549 },
  "calcium-nitrate": { name: "CalGrow Calcium Nitrate", price: 389 },
  "slow-release-npk": { name: "Slow-Release NPK Fertilizer", price: 699 },
  "cow-manure": { name: "Cow Manure Compost", price: 329 },
  "phosphorus-booster": { name: "Phosphorus Booster", price: 459 }
});
const scrypt = promisify(crypto.scrypt);
const sessions = new Map();
let userWriteQueue = Promise.resolve();
let productWriteQueue = Promise.resolve();
let adminPasswordHashPromise;
const adminPasswordSalt = crypto.randomBytes(16);

let orderWriteQueue = Promise.resolve();

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff"
  });
  response.end(JSON.stringify(body));
}

async function readBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, "Request body is too large.");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJsonBody(request) {
  const rawBody = await readBody(request);
  try {
    return JSON.parse(rawBody.toString("utf8"));
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

function assertSameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin || origin === "null") return;
  try {
    const forwardedHost = process.env.TRUST_PROXY === "true" && request.headers["x-forwarded-host"]
      ? String(request.headers["x-forwarded-host"]).split(",")[0].trim()
      : request.headers.host;
    if (new URL(origin).host !== forwardedHost) {
      throw new HttpError(403, "Cross-origin requests are not allowed.");
    }
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(403, "Invalid request origin.");
  }
}

function requiredText(value, label, minimum, maximum) {
  if (typeof value !== "string") throw new HttpError(400, `${label} is required.`);
  const cleaned = value.trim();
  if (cleaned.length < minimum || cleaned.length > maximum || /[\u0000-\u001f\u007f]/.test(cleaned)) {
    throw new HttpError(400, `${label} is invalid.`);
  }
  return cleaned;
}

async function readJsonFile(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return fallback;
    throw error;
  }
}

async function writeJsonFile(file, value) {
  await fs.mkdir(DATA_DIRECTORY, { recursive: true });
  const temporaryFile = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  await fs.writeFile(temporaryFile, JSON.stringify(value, null, 2), { encoding: "utf8", mode: 0o600 });
  await fs.rename(temporaryFile, file);
}

function queueJsonUpdate(queueName, file, fallback, update) {
  const writeQueue = queueName === "users" ? userWriteQueue : productWriteQueue;
  const write = writeQueue.then(async () => {
    const current = await readJsonFile(file, fallback);
    const next = await update(current);
    await writeJsonFile(file, next);
    return next;
  });
  if (queueName === "users") userWriteQueue = write.catch(() => {});
  else productWriteQueue = write.catch(() => {});
  return write;
}

function normalizeEmail(value) {
  const email = requiredText(value, "Email", 3, 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, "Enter a valid email address.");
  return email;
}

function requiredPassword(value) {
  if (typeof value !== "string" || value.length < 8 || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new HttpError(400, "Password must be between 8 and 128 characters.");
  }
  return value;
}

function publicUser(user) {
  return { name: user.name, email: user.email, role: user.role };
}

function requestIsSecure(request) {
  return Boolean(request.socket.encrypted) || (
    process.env.TRUST_PROXY === "true" && request.headers["x-forwarded-proto"] === "https"
  );
}

function sessionCookie(token, request, clear = false) {
  const attributes = [
    `${SESSION_COOKIE}=${clear ? "" : token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${clear ? 0 : SESSION_MAX_AGE_SECONDS}`
  ];
  if (requestIsSecure(request)) attributes.push("Secure");
  return attributes.join("; ");
}

function getSession(request) {
  const cookie = request.headers.cookie || "";
  const token = cookie.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${SESSION_COOKIE}=`))?.slice(SESSION_COOKIE.length + 1);
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}

function requireUser(request) {
  const session = getSession(request);
  if (!session) throw new HttpError(401, "Please log in to continue.");
  return session;
}

function requireAdmin(request) {
  const session = requireUser(request);
  if (session.role !== "admin") throw new HttpError(403, "Administrator access is required.");
  return session;
}

function createSession(response, request, user) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    user: publicUser(user),
    role: user.role,
    expiresAt: Date.now() + SESSION_MAX_AGE_SECONDS * 1000
  });
  response.setHeader("Set-Cookie", sessionCookie(token, request));
  sendJson(response, 200, { user: publicUser(user) });
}

async function readProducts() {
  const customProducts = await readJsonFile(CUSTOM_PRODUCTS_FILE, []);
  if (!Array.isArray(customProducts)) throw new Error("Product store must contain an array.");
  return [...Object.entries(PRODUCTS).map(([id, product]) => ({ id, ...product })), ...customProducts];
}

async function getProductCatalog() {
  return Object.fromEntries((await readProducts()).map(({ id, name, price }) => [id, { name, price }]));
}

async function handleRegister(request, response) {
  assertSameOrigin(request);
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new HttpError(400, "Account details are invalid.");
  const name = requiredText(body.name, "Name", 2, 100);
  const email = normalizeEmail(body.email);
  const password = requiredPassword(body.password);
  if (email === (process.env.ADMIN_EMAIL || "").trim().toLowerCase()) {
    throw new HttpError(409, "This email is reserved for the administrator.");
  }
  const salt = crypto.randomBytes(16);
  const passwordHash = await scrypt(password, salt, 64);
  const user = { name, email, role: "user", salt: salt.toString("hex"), passwordHash: passwordHash.toString("hex") };
  await queueJsonUpdate("users", USERS_FILE, {}, (users) => {
    if (users[email]) throw new HttpError(409, "An account with this email already exists.");
    users[email] = user;
    return users;
  });
  createSession(response, request, user);
}

async function verifyAdminPassword(password) {
  const configuredPassword = process.env.ADMIN_PASSWORD;
  if (!configuredPassword) return false;
  if (!adminPasswordHashPromise) {
    adminPasswordHashPromise = scrypt(configuredPassword, adminPasswordSalt, 64);
  }
  const [expected, received] = await Promise.all([
    adminPasswordHashPromise,
    scrypt(password, adminPasswordSalt, 64)
  ]);
  return crypto.timingSafeEqual(expected, received);
}

async function handleLogin(request, response) {
  assertSameOrigin(request);
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new HttpError(400, "Login details are invalid.");
  const email = normalizeEmail(body.email);
  if (typeof body.password !== "string" || body.password.length < 1 || body.password.length > 128) {
    throw new HttpError(400, "Password is required.");
  }
  const password = body.password;
  const configuredAdminEmail = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  if (configuredAdminEmail && email === configuredAdminEmail) {
    if (!process.env.ADMIN_PASSWORD) throw new HttpError(503, "Administrator login is not configured.");
    if (!(await verifyAdminPassword(password))) throw new HttpError(401, "Email or password is incorrect.");
    createSession(response, request, { name: "Administrator", email, role: "admin" });
    return;
  }
  const users = await readJsonFile(USERS_FILE, {});
  const user = users[email];
  if (!user) throw new HttpError(401, "Email or password is incorrect.");
  const receivedHash = await scrypt(password, Buffer.from(user.salt, "hex"), 64);
  const expectedHash = Buffer.from(user.passwordHash, "hex");
  if (receivedHash.length !== expectedHash.length || !crypto.timingSafeEqual(receivedHash, expectedHash)) {
    throw new HttpError(401, "Email or password is incorrect.");
  }
  createSession(response, request, user);
}

async function handleCreateProduct(request, response) {
  assertSameOrigin(request);
  requireAdmin(request);
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new HttpError(400, "Product details are invalid.");
  const name = requiredText(body.name, "Product name", 2, 100);
  const category = requiredText(body.category, "Category", 1, 40);
  if (!PRODUCT_CATEGORIES.includes(category)) throw new HttpError(400, "Choose a supported product category.");
  if (!Number.isSafeInteger(body.price) || body.price < 1 || body.price > 10000000) {
    throw new HttpError(400, "Price must be a whole number between ₹1 and ₹10,000,000.");
  }
  let image = "";
  if (body.image) {
    image = requiredText(body.image, "Image URL", 1, 500);
    try {
      if (new URL(image).protocol !== "https:") throw new Error("Invalid URL protocol.");
    } catch {
      throw new HttpError(400, "Image URL must use HTTPS.");
    }
  }
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "product";
  const id = `custom-${slug}-${crypto.randomBytes(4).toString("hex")}`;
  const product = { id, name, category, price: body.price, image };
  await queueJsonUpdate("products", CUSTOM_PRODUCTS_FILE, [], (products) => {
    if (!Array.isArray(products)) throw new Error("Product store must contain an array.");
    products.push(product);
    return products;
  });
  sendJson(response, 201, { product });
}

function validateCustomer(customer) {
  if (!customer || typeof customer !== "object" || Array.isArray(customer)) {
    throw new HttpError(400, "Delivery details are required.");
  }
  const details = {
    name: requiredText(customer.name, "Name", 2, 100),
    email: requiredText(customer.email, "Email", 3, 254).toLowerCase(),
    phone: requiredText(customer.phone, "Mobile number", 10, 20),
    address: requiredText(customer.address, "Address", 5, 200),
    city: requiredText(customer.city, "City", 2, 80),
    postalCode: requiredText(customer.postalCode, "PIN code", 6, 6)
  };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(details.email)) {
    throw new HttpError(400, "Enter a valid email address.");
  }
  if (!/^(?:\+?91[\s-]?)?[6-9]\d{9}$/.test(details.phone)) {
    throw new HttpError(400, "Enter a valid 10-digit Indian mobile number.");
  }
  if (!/^\d{6}$/.test(details.postalCode)) {
    throw new HttpError(400, "Enter a valid 6-digit PIN code.");
  }
  return details;
}

async function calculateItems(items) {
  const products = await getProductCatalog();
  if (!Array.isArray(items) || items.length < 1 || items.length > Object.keys(products).length) {
    throw new HttpError(400, "Your cart is empty or invalid.");
  }
  const seen = new Set();
  const validatedItems = items.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new HttpError(400, "A cart item is invalid.");
    }
    const productId = item.productId;
    const product = products[productId];
    if (!Object.hasOwn(products, productId) || seen.has(productId)) {
      throw new HttpError(400, "A cart product is invalid.");
    }
    if (!Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > MAX_QUANTITY) {
      throw new HttpError(400, "Product quantities must be between 1 and 20.");
    }
    seen.add(productId);
    return { productId, name: product.name, price: product.price, quantity: item.quantity };
  });
  const amount = validatedItems.reduce((sum, item) => sum + item.price * item.quantity * 100, 0);
  if (!Number.isSafeInteger(amount) || amount < 100) throw new HttpError(400, "Order total is invalid.");
  return { items: validatedItems, amount };
}

function razorpayCredentials() {
  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;
  if (!keyId || !keySecret) {
    throw new HttpError(503, "Online payments are not configured. Add Razorpay test keys to .env.");
  }
  return { keyId, keySecret };
}

function razorpayIsConfigured() {
  return Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET);
}

function configuredUpiId() {
  const upiId = process.env.UPI_ID?.trim();
  if (!upiId) return "";
  if (!UPI_ID_PATTERN.test(upiId)) throw new HttpError(503, "UPI_ID in .env is not a valid UPI ID.");
  return upiId;
}

async function razorpayRequest(endpoint, method = "GET", body) {
  const { keyId, keySecret } = razorpayCredentials();
  const authorization = Buffer.from(`${keyId}:${keySecret}`).toString("base64");
  const response = await fetch(`https://api.razorpay.com/v1${endpoint}`, {
    method,
    headers: {
      Authorization: `Basic ${authorization}`,
      ...(body ? { "Content-Type": "application/json" } : {})
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(15000)
  });
  const responseText = await response.text();
  let result;
  try {
    result = responseText ? JSON.parse(responseText) : {};
  } catch {
    throw new Error("Razorpay returned an invalid response.");
  }
  if (!response.ok) {
    console.error("Razorpay API error", response.status, result.error?.code || "unknown");
    throw new HttpError(502, "The payment provider could not process this request. Please try again.");
  }
  return result;
}

async function readOrders() {
  try {
    const content = await fs.readFile(ORDERS_FILE, "utf8");
    const orders = JSON.parse(content);
    if (!orders || typeof orders !== "object" || Array.isArray(orders)) {
      throw new Error("Order store must contain an object.");
    }
    return orders;
  } catch (error) {
    if (error.code === "ENOENT") return {};
    throw error;
  }
}

async function saveOrder(order) {
  const write = orderWriteQueue.then(async () => {
    await fs.mkdir(DATA_DIRECTORY, { recursive: true });
    const orders = await readOrders();
    orders[order.orderId] = order;
    const temporaryFile = `${ORDERS_FILE}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    await fs.writeFile(temporaryFile, JSON.stringify(orders, null, 2), { encoding: "utf8", mode: 0o600 });
    await fs.rename(temporaryFile, ORDERS_FILE);
  });
  orderWriteQueue = write.catch(() => {});
  return write;
}

function constantTimeHexEqual(expectedHex, receivedHex) {
  if (typeof receivedHex !== "string" || !/^[a-f\d]{64}$/i.test(receivedHex)) return false;
  const expected = Buffer.from(expectedHex, "hex");
  const received = Buffer.from(receivedHex, "hex");
  return expected.length === received.length && crypto.timingSafeEqual(expected, received);
}

async function handleCreateOrder(request, response) {
  assertSameOrigin(request);
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Order details are invalid.");
  }
  const customer = validateCustomer(body.customer);
  const { items, amount } = await calculateItems(body.items);
  const paymentMethod = requiredText(body.paymentMethod, "Payment method", 1, 20);
  if (!PAYMENT_METHODS.includes(paymentMethod)) throw new HttpError(400, "Choose a supported payment method.");

  const createdAt = new Date().toISOString();
  if (paymentMethod === "cod") {
    const orderId = `cod_${crypto.randomBytes(12).toString("hex")}`;
    await saveOrder({
      orderId,
      amount,
      currency: "INR",
      items,
      customer,
      paymentMethod,
      status: "pending_cod",
      createdAt
    });
    sendJson(response, 201, { mode: "cod", orderId, amount, currency: "INR", status: "pending_cod" });
    return;
  }

  if (paymentMethod === "upi" && !razorpayIsConfigured()) {
    const upiId = configuredUpiId();
    if (!upiId) {
      throw new HttpError(503, "UPI payments are not configured. Configure Razorpay keys or set UPI_ID in .env.");
    }
    const orderId = `upi_${crypto.randomBytes(12).toString("hex")}`;
    await saveOrder({
      orderId,
      amount,
      currency: "INR",
      items,
      customer,
      paymentMethod,
      status: "pending_upi",
      createdAt
    });
    const paymentUrl = new URLSearchParams({
      pa: upiId,
      pn: "Agrihub",
      am: (amount / 100).toFixed(2),
      cu: "INR",
      tn: `Agrihub order ${orderId}`
    });
    sendJson(response, 201, {
      mode: "manual_upi",
      orderId,
      amount,
      currency: "INR",
      upiId,
      paymentUrl: `upi://pay?${paymentUrl.toString()}`,
      status: "pending_upi"
    });
    return;
  }

  const { keyId } = razorpayCredentials();
  const receipt = `farmora_${crypto.randomBytes(12).toString("hex")}`;
  const providerOrder = await razorpayRequest("/orders", "POST", {
    amount,
    currency: "INR",
    receipt,
    notes: {
      item_count: String(items.reduce((sum, item) => sum + item.quantity, 0)),
      payment_method: paymentMethod
    }
  });
  if (!providerOrder.id || providerOrder.amount !== amount || providerOrder.currency !== "INR") {
    throw new HttpError(502, "The payment provider returned an invalid order.");
  }
  await saveOrder({
    orderId: providerOrder.id,
    amount,
    currency: "INR",
    items,
    customer,
    paymentMethod,
    status: "created",
    createdAt
  });
  sendJson(response, 201, {
    mode: "online",
    keyId,
    orderId: providerOrder.id,
    amount,
    currency: "INR",
    paymentMethod
  });
}

async function handlePendingUpiOrders(request, response) {
  requireAdmin(request);
  const orders = await readOrders();
  const pendingOrders = Object.values(orders)
    .filter((order) => order.paymentMethod === "upi" && order.status === "pending_upi")
    .map((order) => ({
      orderId: order.orderId,
      customerName: order.customer.name,
      customerEmail: order.customer.email,
      amount: order.amount,
      currency: order.currency,
      createdAt: order.createdAt
    }));
  sendJson(response, 200, { orders: pendingOrders });
}

async function handleConfirmUpiPayment(request, response, orderId) {
  assertSameOrigin(request);
  requireAdmin(request);
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "UPI verification details are invalid.");
  }
  const transactionReference = requiredText(body.transactionReference, "UPI transaction reference", 6, 64);
  if (!/^[a-zA-Z0-9-]+$/.test(transactionReference)) {
    throw new HttpError(400, "UPI transaction reference is invalid.");
  }
  const orders = await readOrders();
  const order = orders[orderId];
  if (!order) throw new HttpError(404, "Order was not found.");
  if (order.paymentMethod !== "upi" || order.status !== "pending_upi") {
    throw new HttpError(409, "This order is not awaiting UPI verification.");
  }
  if (Object.values(orders).some((existingOrder) => existingOrder.upiTransactionReference === transactionReference)) {
    throw new HttpError(409, "This UPI transaction reference has already been used.");
  }
  const updatedOrder = {
    ...order,
    status: "paid",
    upiTransactionReference: transactionReference,
    paidAt: new Date().toISOString(),
    paymentVerification: "admin_confirmed"
  };
  await saveOrder(updatedOrder);
  sendJson(response, 200, { orderId, status: updatedOrder.status });
}

async function handleLookupOrder(request, response) {
  assertSameOrigin(request);
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Order lookup details are invalid.");
  }
  const orderId = requiredText(body.orderId, "Order ID", 1, 64);
  const email = requiredText(body.email, "Email", 3, 254).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new HttpError(400, "Enter a valid email address.");
  }

  const orders = await readOrders();
  const order = orders[orderId];
  if (!order || order.customer.email !== email) {
    throw new HttpError(404, "We couldn't find that order with this email. Check your details and try again.");
  }

  sendJson(response, 200, {
    orderId: order.orderId,
    status: order.status,
    paymentMethod: order.paymentMethod,
    amount: order.amount,
    currency: order.currency,
    items: order.items.map(({ name, price, quantity }) => ({ name, price, quantity })),
    createdAt: order.createdAt
  });
}

async function handleVerifyPayment(request, response) {
  assertSameOrigin(request);
  const body = await readJsonBody(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Payment details are invalid.");
  }
  const orderId = requiredText(body.orderId, "Order ID", 1, 64);
  const paymentId = requiredText(body.paymentId, "Payment ID", 1, 64);
  const orders = await readOrders();
  const order = orders[orderId];
  if (!order) throw new HttpError(404, "Order was not found. Contact support before retrying payment.");
  if (order.paymentMethod === "cod") throw new HttpError(400, "This order uses cash on delivery.");
  if (order.status === "paid" && order.paymentId === paymentId) {
    sendJson(response, 200, { status: "paid", orderId });
    return;
  }

  const { keySecret } = razorpayCredentials();
  const expectedSignature = crypto.createHmac("sha256", keySecret)
    .update(`${orderId}|${paymentId}`)
    .digest("hex");
  if (!constantTimeHexEqual(expectedSignature, body.signature)) {
    throw new HttpError(400, "Payment signature could not be verified.");
  }

  let payment = await razorpayRequest(`/payments/${encodeURIComponent(paymentId)}`);
  if (
    payment.order_id !== orderId ||
    payment.amount !== order.amount ||
    payment.currency !== order.currency ||
    payment.method !== order.paymentMethod
  ) {
    throw new HttpError(400, "Payment details do not match this order.");
  }
  if (payment.status === "authorized" && !payment.captured) {
    payment = await razorpayRequest(`/payments/${encodeURIComponent(paymentId)}/capture`, "POST", {
      amount: order.amount,
      currency: order.currency
    });
  }
  if (payment.status !== "captured" || payment.captured !== true) {
    throw new HttpError(402, "Payment has not been captured. Please contact support if money was deducted.");
  }

  await saveOrder({
    ...order,
    status: "paid",
    paymentId,
    paidAt: new Date().toISOString()
  });
  sendJson(response, 200, { status: "paid", orderId });
}

async function handleWebhook(request, response) {
  const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
  if (!webhookSecret) throw new HttpError(503, "Payment webhook is not configured.");
  const rawBody = await readBody(request);
  const expectedSignature = crypto.createHmac("sha256", webhookSecret).update(rawBody).digest("hex");
  if (!constantTimeHexEqual(expectedSignature, request.headers["x-razorpay-signature"])) {
    throw new HttpError(400, "Webhook signature could not be verified.");
  }
  let event;
  try {
    event = JSON.parse(rawBody.toString("utf8"));
  } catch {
    throw new HttpError(400, "Webhook body must be valid JSON.");
  }
  if (event.event === "payment.captured") {
    const payment = event.payload?.payment?.entity;
    if (payment?.order_id && payment.id) {
      const orders = await readOrders();
      const order = orders[payment.order_id];
      if (order && payment.amount === order.amount && payment.currency === order.currency) {
        await saveOrder({
          ...order,
          status: "paid",
          paymentId: payment.id,
          paidAt: order.paidAt || new Date().toISOString()
        });
      }
    }
  }
  sendJson(response, 200, { received: true });
}

async function serveStore(response) {
  const html = await fs.readFile(STORE_FILE);
  response.writeHead(200, {
    "Cache-Control": "no-store",
    "Content-Type": "text/html; charset=utf-8",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY"
  });
  response.end(html);
}

async function serveUpiQr(response) {
  const image = await fs.readFile(UPI_QR_FILE);
  response.writeHead(200, {
    "Cache-Control": "public, max-age=3600",
    "Content-Type": "image/jpeg",
    "X-Content-Type-Options": "nosniff"
  });
  response.end(image);
}

async function handleRequest(request, response) {
  try {
    const requestUrl = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    if (request.method === "GET" && (requestUrl.pathname === "/" || requestUrl.pathname === "/product.html")) {
      await serveStore(response);
      return;
    }
    if (request.method === "GET" && requestUrl.pathname === "/assets/upi-payment-qr.jpg") {
      await serveUpiQr(response);
      return;
    }
    if (request.method === "GET" && requestUrl.pathname === "/api/health") {
      sendJson(response, 200, {
        status: "ok",
        paymentsConfigured: razorpayIsConfigured(),
        manualUpiConfigured: Boolean(configuredUpiId()),
        paymentMethods: PAYMENT_METHODS
      });
      return;
    }
    if (request.method === "GET" && requestUrl.pathname === "/api/products") {
      sendJson(response, 200, { products: await readProducts() });
      return;
    }
    if (request.method === "GET" && requestUrl.pathname === "/api/auth/me") {
      const session = getSession(request);
      sendJson(response, 200, { user: session?.user || null });
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/auth/register") {
      await handleRegister(request, response);
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/auth/login") {
      await handleLogin(request, response);
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/auth/logout") {
      assertSameOrigin(request);
      const session = getSession(request);
      if (session) sessions.delete(session.token);
      response.setHeader("Set-Cookie", sessionCookie("", request, true));
      sendJson(response, 200, { user: null });
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/admin/products") {
      await handleCreateProduct(request, response);
      return;
    }
    if (request.method === "GET" && requestUrl.pathname === "/api/admin/orders/pending-upi") {
      await handlePendingUpiOrders(request, response);
      return;
    }
    const confirmUpiMatch = requestUrl.pathname.match(/^\/api\/admin\/orders\/([^/]+)\/confirm-upi$/);
    if (request.method === "POST" && confirmUpiMatch) {
      await handleConfirmUpiPayment(request, response, decodeURIComponent(confirmUpiMatch[1]));
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/orders") {
      await handleCreateOrder(request, response);
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/orders/lookup") {
      await handleLookupOrder(request, response);
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/payments/verify") {
      await handleVerifyPayment(request, response);
      return;
    }
    if (request.method === "POST" && requestUrl.pathname === "/api/webhooks/razorpay") {
      await handleWebhook(request, response);
      return;
    }
    if (request.method !== "GET" && request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    sendJson(response, 404, { error: "Not found." });
  } catch (error) {
    if (response.headersSent) {
      response.destroy(error);
      return;
    }
    if (error instanceof HttpError) {
      sendJson(response, error.status, { error: error.message });
      return;
    }
    console.error("Request failed:", error);
    sendJson(response, 500, { error: "An unexpected server error occurred. Please try again." });
  }
}

function createServer() {
  return http.createServer(handleRequest);
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3001);
  const host = process.env.HOST || "127.0.0.1";
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("PORT must be an integer between 1 and 65535.");
  }
  createServer().listen(port, host, () => {
    console.log(`Agrihub is listening at http://${host}:${port}`);
  });
}

module.exports = { createServer, PRODUCTS };
