# Agrihub store

Agrihub is a fertilizer storefront with featured products, product search, category filters, sorting, a cart, customer accounts, and guest checkout. Registered customers can log in; administrators can add products from the storefront. Payments can use Razorpay Standard Checkout; direct UPI and cash on delivery are available without Razorpay.

Customers can create an account from **Log in**; passwords are stored as scrypt hashes. Administrator sign-in uses the credentials configured in `.env`. Product records and customer accounts are saved in `data/products.json` and `data/users.json`; the administrator product form is available only in the authenticated admin session. Sessions are held by the server and use HttpOnly, SameSite cookies.

## Run locally

1. Install Node.js 22 or newer.
2. Copy `.env.example` to `.env` if needed:

   ```powershell
   Copy-Item .env.example .env
   ```

3. Configure `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD` in `.env` to enable the administrator account. Do not use these credentials for customer accounts, and never commit `.env`.
4. To accept direct UPI payments, set `UPI_ID` in `.env`. The supplied QR is shown after checkout with the order amount and ID. Customers should scan it, pay the exact amount, and include the order ID as the payment note. Direct UPI orders remain pending until an administrator checks the received payment and confirms it with the transaction reference in the admin panel. Never mark an order paid based only on the customer's claim.
5. To enable Razorpay for UPI, cards, and netbanking, create **Test Mode** API keys in the Razorpay Dashboard and set `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` in `.env`. Never put the secret in the page or commit `.env`.
6. Start the store from this folder:

   ```powershell
   npm start
   ```

7. Open `http://127.0.0.1:3001`. Use this numeric address rather than `localhost` on this machine, where another application responds to `localhost:3001`.

Checkout totals and product prices are recalculated on the server. Online orders are verified against Razorpay signatures and captured payment records before confirmation. PhonePe is offered through the UPI option when supported by the gateway account and customer's device; the bank option uses netbanking. COD orders are saved with `pending_cod` status in `data/orders.json`; collect the amount at delivery and update fulfillment status through your order-management process. **My Orders** automatically looks up the latest completed order from the current page session; customers can also enter an order ID and checkout email to see a privacy-limited summary for another order.

For production payment updates, configure a Razorpay webhook at `https://YOUR_DOMAIN/api/webhooks/razorpay`, subscribe to `payment.captured`, and set `RAZORPAY_WEBHOOK_SECRET`. Use live keys only after the merchant account is approved and the site is deployed over HTTPS. Set `HOST=0.0.0.0` when the hosting platform requires binding to all interfaces.

## Run tests

Run `npm test` to verify online order creation, server-side pricing, payment verification, webhook signatures, COD order storage, and checkout options using a mocked Razorpay API. Tests do not make real payments or require merchant credentials.
