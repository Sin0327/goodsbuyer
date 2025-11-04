const Koa = require("koa");
const Router = require("koa-router");
const bodyParser = require("koa-bodyparser");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const session = require("koa-session");
const {
  getPKCEAuthenticationUrl,
  getPKCEOAuthToken,
  refreshOAuthToken,
} = require("@coze/api");
const cors = require('@koa/cors');
const REDIRECT_URI = "http://127.0.0.1:8080/callback";
const configPath = path.join(__dirname, "coze_oauth_config.json");

// Load configuration file
function loadConfig() {
  // Check if configuration file exists
  if (!fs.existsSync(configPath)) {
    throw new Error(
      "Configuration file coze_oauth_config.json does not exist!"
    );
  }

  // Read configuration file
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));

  // Validate required fields
  const requiredFields = [
    "client_type",
    "client_id",
    "coze_www_base",
    "coze_api_base",
  ];

  for (const field of requiredFields) {
    if (!config[field]) {
      throw new Error(`Configuration file missing required field: ${field}`);
    }
    if (Array.isArray(config[field]) && config[field].length === 0) {
      throw new Error(`Configuration field ${field} cannot be an empty array`);
    }
    if (typeof config[field] === "string" && !config[field].trim()) {
      throw new Error(`Configuration field ${field} cannot be an empty string`);
    }
  }

  return config;
}

// Read and process HTML template
function renderTemplate(templatePath, variables) {
  try {
    let template = fs.readFileSync(templatePath, "utf8");

    // Replace all variables in {{variable}} format
    Object.keys(variables).forEach((key) => {
      const regex = new RegExp(`{{${key}}}`, "g");
      template = template.replace(regex, variables[key]);
    });

    return template;
  } catch (error) {
    console.error("Template rendering error:", error);
    throw error;
  }
}

// Utility function: Convert timestamp to date string
function timestampToDatetime(timestamp) {
  return new Date(timestamp * 1000).toLocaleString();
}

// Load configuration
const config = loadConfig();

const app = new Koa();
const router = new Router();

// Session configuration
const SESSION_CONFIG = {
  key: "koa:sess",
  maxAge: 86400000,
  autoCommit: true,
  overwrite: true,
  httpOnly: true,
  signed: true,
  rolling: false,
  renew: false,
};

// Set the keys for cookie signing
app.keys = [crypto.randomBytes(32).toString("hex")];

// Apply session middleware
app.use(session.createSession(SESSION_CONFIG, app));

// Use bodyParser middleware
app.use(bodyParser());

// Use CORS middleware
app.use(
  cors({
    credentials: true, // Support Request With Cookies
    origin: ctx => {
      const requestOrigin = ctx.get('Origin');
      return requestOrigin || 'http://127.0.0.1:8080';
    },
  }),
);

// Static file service middleware
app.use(async (ctx, next) => {
  if (ctx.path.startsWith("/assets/")) {
    try {
      // Point to websites/assets directory for static resources
      const filePath = path.join(__dirname, "websites", ctx.path);
      ctx.type = path.extname(filePath);
      ctx.body = fs.createReadStream(filePath);
    } catch (error) {
      console.error("Static resource access error:", error);
      ctx.status = 404;
    }
  } else {
    await next();
  }
});

// Serve root-level images like /image_1.png or /image.png to avoid 404
app.use(async (ctx, next) => {
  try {
    if (/^\/image(_\d+)?\.png$/i.test(ctx.path)) {
      const filename = ctx.path.replace(/^\//, "");
      const filePath = path.join(__dirname, filename);
      if (fs.existsSync(filePath)) {
        ctx.type = path.extname(filePath);
        ctx.body = fs.createReadStream(filePath);
        return;
      } else {
        ctx.status = 404;
        ctx.body = "Not Found";
        return;
      }
    }
    if (ctx.path === "/favicon.ico") {
      const icoPath = path.join(__dirname, "websites", "assets", "coze.png");
      if (fs.existsSync(icoPath)) {
        ctx.type = "png";
        ctx.body = fs.createReadStream(icoPath);
        return;
      }
    }
  } catch (error) {
    console.error("Static image access error:", error);
    ctx.status = 500;
    ctx.body = "Server Error: " + error.message;
    return;
  }
  await next();
});

// Home route: serve project root index.html as the main UI
router.get("/", async (ctx) => {
  try {
    const filePath = path.join(__dirname, "index.html");
    ctx.type = "html";
    ctx.body = fs.createReadStream(filePath);
  } catch (error) {
    console.error("Failed to serve home page:", error);
    ctx.status = 500;
    ctx.body = "Server Error: " + error.message;
  }
});

// Login route
router.get("/login", async (ctx) => {
  try {
    const { codeVerifier, url } = await getPKCEAuthenticationUrl({
      baseURL: config.coze_api_base,
      clientId: config.client_id,
      redirectUrl: REDIRECT_URI,
    });

    // Store code_verifier in session
    ctx.session.codeVerifier = codeVerifier;

    ctx.redirect(url);
  } catch (error) {
    console.error("Failed to generate authorization URL:", error);
    ctx.status = 500;
    ctx.body = renderTemplate(path.join(__dirname, "websites", "error.html"), {
      error: `Failed to generate authorization URL: ${error.message}`,
    });
  }
});

// OAuth callback route
router.get("/callback", async (ctx) => {
  const { code } = ctx.query;
  const codeVerifier = ctx.session.codeVerifier;

  if (!code) {
    ctx.status = 400;
    return (ctx.body = renderTemplate(
      path.join(__dirname, "websites", "error.html"),
      { error: "Authorization failed: No authorization code received" }
    ));
  }

  if (!codeVerifier) {
    ctx.status = 400;
    return (ctx.body = renderTemplate(
      path.join(__dirname, "websites", "error.html"),
      { error: "Authorization failed: No code verifier found" }
    ));
  }

  try {
    // Get access token using PKCE
    const oauthToken = await getPKCEOAuthToken({
      baseURL: config.coze_api_base,
      clientId: config.client_id,
      code: code,
      redirectUrl: REDIRECT_URI,
      codeVerifier: codeVerifier,
    });

    // Persist token in session for subsequent API/SDK usage
    ctx.session.oauth = {
      token_type: "pkce",
      access_token: oauthToken.access_token,
      refresh_token: oauthToken.refresh_token,
      // Some SDKs return expires_in as lifetime seconds; store both raw and computed expireAt
      expires_in: oauthToken.expires_in,
      expire_at: Date.now() + (Number(oauthToken.expires_in) || 0) * 1000,
    };

    // Render callback page
    const expiresStr = timestampToDatetime(oauthToken.expires_in);
    ctx.body = renderTemplate(
      path.join(__dirname, "websites", "callback.html"),
      {
        token_type: "pkce",
        access_token: oauthToken.access_token,
        refresh_token: oauthToken.refresh_token,
        expires_in: `${oauthToken.expires_in} (${expiresStr})`,
      }
    );
  } catch (error) {
    console.error("Failed to get access token:", error);
    ctx.status = 500;
    ctx.body = renderTemplate(path.join(__dirname, "websites", "error.html"), {
      error: `Failed to get access token: ${error.message}`,
    });
  }
});

// Refresh token route
router.post("/refresh_token", async (ctx) => {
  try {
    let { refresh_token } = ctx.request.body || {};
    // Fallback to session refresh token when not provided in request body
    if (!refresh_token && ctx.session && ctx.session.oauth && ctx.session.oauth.refresh_token) {
      refresh_token = ctx.session.oauth.refresh_token;
    }

    if (!refresh_token) {
      ctx.status = 401;
      return (ctx.body = { error: "No refresh token available. Please re-login." });
    }

    // Refresh access token
    const oauthToken = await refreshOAuthToken({
      baseURL: config.coze_api_base,
      clientId: config.client_id,
      refreshToken: refresh_token,
    });

    const expiresStr = timestampToDatetime(oauthToken.expires_in);
    // Update session with new tokens
    ctx.session.oauth = {
      token_type: "pkce",
      access_token: oauthToken.access_token,
      refresh_token: oauthToken.refresh_token,
      expires_in: oauthToken.expires_in,
      expire_at: Date.now() + (Number(oauthToken.expires_in) || 0) * 1000,
    };

    ctx.body = {
      token_type: "pkce",
      access_token: oauthToken.access_token,
      refresh_token: oauthToken.refresh_token,
      expires_in: `${oauthToken.expires_in} (${expiresStr})`,
    };
  } catch (error) {
    console.error("Failed to refresh token:", error);
    ctx.status = 500;
    ctx.body = { error: `Failed to refresh token: ${error.message}` };
  }
});

// Access token route for frontend chat page
router.get("/token", async (ctx) => {
  try {
    // 优先返回 OAuth 会话令牌；未登录则回退到公共 PAT 令牌
    const oauth = ctx.session && ctx.session.oauth;
    if (oauth && oauth.access_token) {
      const resp = { token_type: oauth.token_type || "pkce", access_token: oauth.access_token };
      try {
        const host = ctx.request.header.host;
        console.log(`[token] host=${host} type=${resp.token_type} token_len=${(resp.access_token||'').length}`);
      } catch(e) {}
      ctx.body = resp;
      return;
    }

    // 公共模式：返回配置中的 PAT 令牌（用于 WebSDK 访客）
    const pat = (process.env.COZE_PAT || config.websdk_pat || config.pat || '').trim();
    if (pat) {
      const resp = { token_type: 'pat', access_token: pat };
      try {
        const host = ctx.request.header.host;
        console.log(`[token] host=${host} type=${resp.token_type} token_len=${(resp.access_token||'').length}`);
      } catch(e) {}
      ctx.body = resp;
      return;
    }

    // 无可用令牌时提示配置缺失
    ctx.status = 401;
    ctx.body = { error: "Public PAT not configured. Set env COZE_PAT or websdk_pat in coze_oauth_config.json." };
  } catch (error) {
    console.error("Failed to provide token:", error);
    ctx.status = 500;
    ctx.body = { error: `Failed to provide token: ${error.message}` };
  }
});

// Logout route to clear session
router.post("/logout", async (ctx) => {
  ctx.session = null;
  ctx.status = 200;
  ctx.body = { ok: true };
});

// Serve chat page from root file
router.get("/chat", async (ctx) => {
  try {
    const filePath = path.join(__dirname, "chat-sdk.html");
    ctx.type = "html";
    ctx.body = fs.createReadStream(filePath);
  } catch (error) {
    console.error("Failed to serve chat page:", error);
    ctx.status = 500;
    ctx.body = "Server Error: " + error.message;
  }
});

// Serve local images (e.g., /image_1.png) for the homepage visual
router.get("/image_:id.png", async (ctx) => {
  try {
    const id = ctx.params.id;
    const filename = `image_${id}.png`;
    const filePath = path.join(__dirname, filename);
    if (fs.existsSync(filePath)) {
      ctx.type = "png";
      ctx.body = fs.createReadStream(filePath);
    } else {
      ctx.status = 404;
      ctx.body = "Not Found";
    }
  } catch (error) {
    console.error("Failed to serve image:", error);
    ctx.status = 500;
    ctx.body = "Server Error: " + error.message;
  }
});

// Serve root sample image /image.png for header logo
router.get("/image.png", async (ctx) => {
  try {
    const filePath = path.join(__dirname, "image.png");
    if (fs.existsSync(filePath)) {
      ctx.type = "png";
      ctx.body = fs.createReadStream(filePath);
    } else {
      ctx.status = 404;
      ctx.body = "Not Found";
    }
  } catch (error) {
    console.error("Failed to serve sample image:", error);
    ctx.status = 500;
    ctx.body = "Server Error: " + error.message;
  }
});

// Register routes
app.use(router.routes()).use(router.allowedMethods());

// Start server
const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`Server running on port http://127.0.0.1:${port}`);
});
