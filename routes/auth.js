var express = require('express');
var fetch = require('node-fetch');
var crypto = require('crypto');
var router = express.Router();

/**
 * Validates the HMAC signature from Shopify
 * @param {Object} query - The query parameters from the request
 * @returns {boolean} - True if HMAC is valid, false otherwise
 */
function verifyHmac(query) {
  const { hmac, ...params } = query;

  if (!hmac) {
    return false;
  }

  // Sort parameters alphabetically and create query string
  const sortedParams = Object.keys(params)
    .sort()
    .map(key => `${key}=${params[key]}`)
    .join('&');

  // Generate HMAC using SHA256
  const hash = crypto
    .createHmac('sha256', process.env.SHOPIFY_API_SECRET)
    .update(sortedParams)
    .digest('hex');

  // Compare the generated hash with the one from Shopify
  return hash === hmac;
}

/**
 * Validates that the shop domain is a valid myshopify.com domain
 * @param {string} shop - The shop domain
 * @returns {boolean} - True if valid, false otherwise
 */
function isValidShopDomain(shop) {
  const shopRegex = /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/;
  return shopRegex.test(shop);
}

// GET /auth?shop=store-name.myshopify.com
router.get('/', function(req, res, next) {
  const shop = req.query.shop;
  if (!shop) {
    return res.status(400).send('Missing shop parameter');
  }

  // Validate shop domain format
  if (!isValidShopDomain(shop)) {
    return res.status(400).send('Invalid shop domain');
  }

  const redirectUri = `${process.env.HOST}/auth/callback`;
  const nonce = crypto.randomBytes(16).toString('hex');

  // Store nonce in session for validation in callback (CSRF protection)
  req.session.state = nonce;
  req.session.shop = shop;

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${process.env.SHOPIFY_API_KEY}` +
    `&scope=${process.env.SCOPES}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${nonce}`;

  res.redirect(installUrl);
});

// GET /auth/callback - Handle Shopify OAuth redirect
router.get('/callback', async function(req, res, next) {
  const { shop, code, hmac, state } = req.query;

  if (!shop || !code || !hmac) {
    return res.status(400).send('Required parameters missing');
  }

  // Validate shop domain format
  if (!isValidShopDomain(shop)) {
    return res.status(400).send('Invalid shop domain');
  }

  // Verify state/nonce to prevent CSRF attacks
  /*if (!state || !req.session.state || state !== req.session.state) {
    console.error('State validation failed');
    return res.status(403).send('State validation failed - possible CSRF attack');
  }*/

  // Verify that the shop matches the one stored in session
  /*if (shop !== req.session.shop) {
    console.error('Shop mismatch in session');
    return res.status(403).send('Shop validation failed');
  }*/

  // Verify HMAC signature
  if (!verifyHmac(req.query)) {
    console.error('HMAC validation failed');
    return res.status(403).send('HMAC validation failed - request may not be from Shopify');
  }

  // Clear the state from session after successful validation
  const validatedShop = req.session.shop;
  delete req.session.state;
  delete req.session.shop;

  try {
    // Exchange auth code for access token
    const tokenResponse = await fetch(
      `https://${shop}/admin/oauth/access_token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: process.env.SHOPIFY_API_KEY,
          client_secret: process.env.SHOPIFY_API_SECRET,
          code,
        }),
      }
    );

    if (!tokenResponse.ok) {
      throw new Error(`Token exchange failed: ${tokenResponse.statusText}`);
    }

    const tokenJson = await tokenResponse.json();
    const accessToken = tokenJson.access_token;

    if (!accessToken) {
      throw new Error('No access token received from Shopify');
    }

    // TODO: store accessToken in a database associated with the shop domain
    console.log(`Access token received for shop: ${validatedShop}`);
    console.log(`Access token: ${accessToken}`);

    // Redirect to your frontend UI
    res.redirect(`${process.env.FRONTEND_URL}/?shop=${validatedShop}`);
  } catch (error) {
    console.error('Error during OAuth callback:', error);
    res.status(500).send('Authentication failed: ' + error.message);
  }
});

module.exports = router;
